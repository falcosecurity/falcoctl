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

package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/falcosecurity/falcoctl/cmd/internal/utils"
	"github.com/falcosecurity/falcoctl/pkg/index"
	"github.com/falcosecurity/falcoctl/pkg/oci"
	"github.com/falcosecurity/falcoctl/pkg/oci/authn"
	ocipuller "github.com/falcosecurity/falcoctl/pkg/oci/puller"
	"github.com/falcosecurity/falcoctl/pkg/options"
)

const (
	defaultPluginsDir    = "/usr/share/falco/plugins"
	defaultRulesfilesDir = "/etc/falco"
)

type artifactInstallOptions struct {
	*options.CommonOptions
	credentialStore *authn.Store
	rulesfilesDir   string
	pluginsDir      string
}

// NewArtifactInstallCmd returns the artifact search command.
func NewArtifactInstallCmd(ctx context.Context, opt *options.CommonOptions) *cobra.Command {
	o := artifactInstallOptions{
		CommonOptions: opt,
	}

	cmd := &cobra.Command{
		Use:                   "install [ref1 [ref2 ...]] [flags]",
		DisableFlagsInUseLine: true,
		Short:                 "Install a list of artifacts",
		Long:                  "Install a list of artifacts",
		Args:                  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			o.Printer.CheckErr(o.RunArtifactInstall(ctx, args))
		},
	}

	cmd.Flags().StringVarP(&o.rulesfilesDir, "rulesfiles-dir", "", defaultRulesfilesDir,
		"directory where to install rules. Defaults to /etc/falco")
	cmd.Flags().StringVarP(&o.pluginsDir, "plugins-dir", "", defaultPluginsDir,
		"directory where to install plugins. Defaults to /usr/share/falco/plugins")

	return cmd
}

// RunArtifactInstall executes the business logic for the artifact install command.
func (o *artifactInstallOptions) RunArtifactInstall(ctx context.Context, args []string) error {
	o.Printer.Info.Printfln("Reading all configured index files from %q", indexesFile)
	indexConfig, err := index.NewConfig(indexesFile)
	if err != nil {
		return err
	}

	mergedIndexes, err := utils.Indexes(indexConfig, falcoctlPath)
	if err != nil {
		return err
	}

	o.credentialStore, err = authn.NewStore([]string{}...)
	if err != nil {
		return err
	}

	// Create temp dir where to put pulled artifacts
	tmpDir, err := os.MkdirTemp("", "falcoctl")
	if err != nil {
		return fmt.Errorf("cannot create temporary directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// Install artifacts
	for _, name := range args {
		ref, err := utils.ParseReference(mergedIndexes, name)
		if err != nil {
			return err
		}

		o.Printer.Info.Printfln("Preparing to pull %q", ref)

		reg, err := utils.GetRegistryFromRef(ref)
		if err != nil {
			return err
		}

		puller, err := o.getPuller(ctx, reg)
		if err != nil {
			return err
		}

		// Install will always install artifact for the current OS and architecture
		result, err := puller.Pull(ctx, ref, tmpDir, runtime.GOOS, runtime.GOARCH)
		if err != nil {
			return err
		}

		var destDir string
		switch result.Type {
		case oci.Plugin:
			destDir = o.pluginsDir
		case oci.Rulesfile:
			destDir = o.rulesfilesDir
		}

		sp, _ := o.Printer.Spinner.Start(fmt.Sprintf("Extracting and installing %q %q", result.Type, result.Filename))
		result.Filename = filepath.Join(tmpDir, result.Filename)

		f, err := os.Open(result.Filename)
		if err != nil {
			return err
		}

		// Extract artifact and move it to its destination directory
		err = utils.ExtractTarGz(f, destDir)
		if err != nil {
			return err
		}

		err = os.Remove(result.Filename)
		if err != nil {
			return err
		}

		sp.Success(fmt.Sprintf("Artifact successfully installed in %q", destDir))
	}

	return nil
}

func (o *artifactInstallOptions) getPuller(ctx context.Context, reg string) (*ocipuller.Puller, error) {
	cred, err := o.credentialStore.Credential(ctx, reg)
	if err != nil {
		return nil, err
	}

	if err := utils.CheckRegistryConnection(ctx, &cred, reg, o.Printer); err != nil {
		o.Printer.Verbosef("%s", err.Error())
		return nil, fmt.Errorf("unable to connect to registry %q", reg)
	}

	client := authn.NewClient(cred)

	puller := ocipuller.NewPuller(client, newPullProgressTracker(o.Printer))

	return puller, nil
}
