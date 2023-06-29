// Copyright 2022 The Falco Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package follower

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/blang/semver"
	"github.com/robfig/cron/v3"
	"oras.land/oras-go/v2/registry"

	"github.com/falcosecurity/falcoctl/internal/config"
	"github.com/falcosecurity/falcoctl/internal/sign"
	"github.com/falcosecurity/falcoctl/internal/utils"
	"github.com/falcosecurity/falcoctl/pkg/index"
	"github.com/falcosecurity/falcoctl/pkg/oci"
	ocipuller "github.com/falcosecurity/falcoctl/pkg/oci/puller"
	ociutils "github.com/falcosecurity/falcoctl/pkg/oci/utils"
	"github.com/falcosecurity/falcoctl/pkg/output"
)

// Follower knows how to track an artifact in a remote repository given the reference.
// It starts a new goroutine to check for updates periodically. If an update is available
// it pulls the new version and installs it in the correct directory.
type Follower struct {
	ref           string
	tag           string
	tmpDir        string
	currentDigest string
	*ocipuller.Puller
	*Config
	*output.Printer
	config.FalcoVersions
}

// Config configuration options for the Follower.
type Config struct {
	WaitGroup *sync.WaitGroup
	// CloseChan used to close the follower.
	CloseChan <-chan bool
	// Resync time after which periodically it checks for new a new version.
	Resync cron.Schedule
	// RulesfileDir directory where the rulesfile are stored.
	RulesfilesDir string
	// PluginsDir directory where the plugins are stored.
	PluginsDir string
	// ArtifactReference reference to the artifact in a remote repository.
	ArtifactReference string
	// PlainHTTP is set to true if all registry interaction must be in plain http.
	PlainHTTP bool
	// Verbose enables the verbose logs.
	Verbose bool
	// TmpDir directory where to save temporary files.
	TmpDir string
	// FalcoVersions is a struct containing all the required Falco versions that this follower
	// has to take into account when installing artifacts.
	FalcoVersions config.FalcoVersions
	// AllowedTypes specify a list of artifacts that we are allowed to download.
	AllowedTypes oci.ArtifactTypeSlice
	// Signature has the data needed for signature checking
	Signature *index.Signature
}

var (
	isInt = regexp.MustCompile(`^(0|([1-9]\d*))$`)
)

// New creates a Follower configured with the passed parameters and ready to be used.
// It does not check the correctness of the parameters, make sure everything is initialized.
func New(ref string, printer *output.Printer, conf *Config) (*Follower, error) {
	_, err := utils.GetRegistryFromRef(ref)
	if err != nil {
		return nil, fmt.Errorf("unable to extract registry from ref %q: %w", ref, err)
	}

	parsedRef, err := registry.ParseReference(ref)
	if err != nil {
		return nil, fmt.Errorf("unable to extract tag from ref %q: %w", ref, err)
	}
	tag := parsedRef.Reference

	client, err := ociutils.Client()
	if err != nil {
		return nil, err
	}

	puller := ocipuller.NewPuller(client, conf.PlainHTTP, nil)
	if err != nil {
		return nil, err
	}

	// Create temp dir where to put pulled artifacts.
	tmpDir, err := os.MkdirTemp(conf.TmpDir, "falcoctl-")
	if err != nil {
		return nil, fmt.Errorf("unable to create temporary directory: %w", err)
	}

	customPrinter := printer.WithScope(ref)

	return &Follower{
		ref:           ref,
		tag:           tag,
		tmpDir:        tmpDir,
		Puller:        puller,
		Config:        conf,
		Printer:       customPrinter,
		FalcoVersions: conf.FalcoVersions,
	}, nil
}

// Follow starts a goroutine that periodically checks for updates for the configured artifact.
func (f *Follower) Follow(ctx context.Context) {
	// At start up time of the follower we sync immediately without waiting the resync time.
	f.follow(ctx)

	for {
		now := time.Now()
		next := f.Resync.Next(now)
		select {
		case <-f.CloseChan:
			f.cleanUp()
			fmt.Printf("follower for %q stopped\n", f.ref)
			// Notify that the follower is done.
			f.WaitGroup.Done()
			return
		case <-time.After(next.Sub(now)):
			// Start following the artifact.
			f.follow(ctx)
		}
	}
}

func (f *Follower) follow(ctx context.Context) {
	// First thing get the descriptor from remote repo.
	f.Verbosef("fetching descriptor from remote repository...")
	desc, err := f.Descriptor(ctx, f.ref)
	if err != nil {
		f.Error.Printfln("an error occurred while fetching descriptor from remote repository: %v", err)
		return
	}
	f.Verbosef("descriptor correctly fetched")

	// If we have already processed then do nothing.
	// TODO(alacuku): check that the file also exists to cover the case when someone has removed the file.
	if desc.Digest.String() == f.currentDigest {
		f.Verbosef("nothing to do, artifact already up to date.")
		return
	}

	f.Info.Printfln("found new version under tag %q", f.tag)

	// Pull config layer to check falco versions
	artifactConfig, err := f.PullConfigLayer(ctx, f.ref)
	if err != nil {
		f.Error.Printfln("unable to pull config layer for ref %q: %v", f.ref, err)
		return
	}

	err = f.checkRequirements(artifactConfig)
	if err != nil {
		f.Error.Printfln("unmet requirements for ref %q: %v", f.ref, err)
		return
	}

	f.Verbosef("pulling artifact from remote repository...")
	// Pull the artifact from the repository.
	filePaths, res, err := f.pull(ctx)
	if err != nil {
		f.Error.Printfln("an error occurred while pulling artifact from remote repository: %v", err)
		return
	}
	f.Verbosef("artifact correctly pulled")

	dstDir := f.destinationDir(res)

	// Check if directory exists and is writable.
	err = utils.ExistsAndIsWritable(dstDir)
	if err != nil {
		f.Error.Printfln("cannot use directory %q as install destination: %v", dstDir, err)
		return
	}

	// Install the artifacts if necessary.
	for _, path := range filePaths {
		baseName := filepath.Base(path)
		f.Verbosef("installing file %q...", baseName)
		dstPath := filepath.Join(dstDir, baseName)
		// Check if the file exists.
		f.Verbosef("checking if file %q already exists in %q", baseName, dstDir)
		exists, err := fileExists(dstPath)
		if err != nil {
			f.Error.Printfln("an error occurred while checking %q existence: %v", baseName, err)
			return
		}

		if !exists {
			f.Verbosef("file %q does not exist in %q, moving it", baseName, dstDir)
			if err = utils.Move(path, dstPath); err != nil {
				f.Error.Printfln("an error occurred while moving file %q to %q: %v", baseName, dstDir, err)
				return
			}
			f.Verbosef("file %q correctly installed", path)
			// It's done, move to the next file.
			continue
		}
		f.Verbosef("file %q already exists in %q, checking if it is equal to the existing one", baseName, dstDir)
		// Check if the files are equal.
		eq, err := equal([]string{path, dstPath})
		if err != nil {
			f.Error.Printfln("an error occurred while comparing files %q and %q: %v", path, dstPath, err)
			return
		}

		if !eq {
			f.Verbosef("overwriting file %q with file %q", dstPath, path)
			if err = utils.Move(path, dstPath); err != nil {
				f.Error.Printfln("an error occurred while overwriting file %q: %v", dstPath, err)
				return
			}
		} else {
			f.Verbosef("the two file are equal, nothing to be done")
		}
	}

	f.Info.Printfln("artifact with tag %q correctly installed", f.tag)
	f.currentDigest = desc.Digest.String()
}

// pull downloads, extracts, and installs the artifact.
func (f *Follower) pull(ctx context.Context) (filePaths []string, res *oci.RegistryResult, err error) {
	f.Verbosef("check if pulling an allowed type of artifact")
	if err := f.Puller.CheckAllowedType(ctx, f.ref, f.Config.AllowedTypes.Types); err != nil {
		return nil, nil, err
	}

	// Pull the artifact from the repository.
	f.Verbosef("pulling artifact %q", f.ref)
	res, err = f.Pull(ctx, f.ref, f.tmpDir, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return filePaths, res, fmt.Errorf("unable to pull artifact %q: %w", f.ref, err)
	}

	// Verify the signature if needed
	if f.Config.Signature != nil {
		f.Verbosef("verifying signature")
		err = sign.VerifySignature(res.RootDigest, f.Config.Signature)
		if err != nil {
			return filePaths, res, fmt.Errorf("could not verify signature for %s: %w", res.RootDigest, err)
		}
	}

	f.Verbosef("extracting artifact")
	res.Filename = filepath.Join(f.tmpDir, res.Filename)

	file, err := os.Open(res.Filename)
	if err != nil {
		return filePaths, res, fmt.Errorf("unable to open file %q: %w", res.Filename, err)
	}

	// Extract artifact and move it to its destination directory
	filePaths, err = utils.ExtractTarGz(file, f.tmpDir)
	if err != nil {
		return filePaths, res, fmt.Errorf("unable to extract %q to %q: %w", res.Filename, f.tmpDir, err)
	}

	f.Verbosef("cleaning up leftovers files")
	err = os.Remove(res.Filename)
	if err != nil {
		return filePaths, res, fmt.Errorf("unable to remove file %q: %w", res.Filename, err)
	}

	return filePaths, res, err
}

// destinationDir returns the dir where to save the artifact.
func (f *Follower) destinationDir(res *oci.RegistryResult) string {
	var dir string
	switch res.Type {
	case oci.Plugin:
		dir = f.PluginsDir
	case oci.Rulesfile:
		dir = f.RulesfilesDir
	}
	return dir
}

func (f *Follower) checkRequirements(artifactConfig *oci.ArtifactConfig) error {
	// Check if each requirement specified in a config layer meet the needs of the
	// currently running Falco.

	for _, requirement := range artifactConfig.Requirements {
		reqName := requirement.Name
		falcoVer, ok := f.FalcoVersions[requirement.Name]
		if !ok {
			return fmt.Errorf("unrecognized key %s: Falco does not satisfy this requirement", reqName)
		}
		if isInt.MatchString(requirement.Version) { // handle integers
			falcoVerInt, err := strconv.Atoi(falcoVer)
			if err != nil {
				return fmt.Errorf("expected integer for key %s: %w", reqName, err)
			}

			reqVerInt, err := strconv.Atoi(requirement.Version)
			if err != nil {
				return fmt.Errorf("expected integer for key %s: %w", reqName, err)
			}

			if falcoVerInt < reqVerInt {
				return fmt.Errorf("incompatible versions, Falco: %d, Requirement: %s:%d", falcoVerInt, reqName, reqVerInt)
			}
		} else { // handle semver
			falcoSemver, err := semver.Parse(falcoVer)
			if err != nil {
				return fmt.Errorf("expected semver for key %s: %w", reqName, err)
			}

			reqSemver, err := semver.Parse(requirement.Version)
			if err != nil {
				return fmt.Errorf("expected semver for key %s: %w", reqName, err)
			}

			// Normal semver check
			if falcoSemver.Major != reqSemver.Major {
				return fmt.Errorf("incompatible versions, MAJOR mismatch, Falco: %s, Requirement: %s:%s", falcoSemver.String(), reqName, reqSemver.String())
			} else if falcoSemver.Compare(reqSemver) < 0 {
				return fmt.Errorf("incompatible versions, MINOR mismatch, Falco: %s, Requirement: %s:%s", falcoSemver.String(), reqName, reqSemver.String())
			}
		}
	}

	return nil
}

func (f *Follower) cleanUp() {
	if err := os.RemoveAll(f.tmpDir); err != nil {
		f.DefaultText.Printfln("an error occurred while removing working directory %q:%v", f.tmpDir, err)
	}
}

// fileExists checks if a file exists on disk.
func fileExists(filename string) (bool, error) {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false, nil
	}

	if err != nil {
		return false, err
	}

	return !info.IsDir(), nil
}

// equal checks if the two files are equal by comparing their sha256 hashes.
func equal(files []string) (bool, error) {
	var hashes []string
	if len(files) != 2 {
		return false, fmt.Errorf("expecting 2 files but got %d", len(files))
	}

	hasher := sha256.New()

	for _, file := range files {
		filePath := filepath.Clean(file)
		f, err := os.Open(filePath)
		if err != nil {
			return false, err
		}

		if _, err := io.Copy(hasher, f); err != nil {
			return false, err
		}
		hashes = append(hashes, string(hasher.Sum([]byte{})))

		// Clean up.
		if err := f.Close(); err != nil {
			return false, fmt.Errorf("unable to close file %q: %w", filePath, err)
		}

		hasher.Reset()
	}

	if hashes[0] != hashes[1] {
		return false, nil
	}

	return true, nil
}
