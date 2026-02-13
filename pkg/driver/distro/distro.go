// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 The Falco Authors
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

// Package driverdistro implements all the distro specific driver-related logic.
package driverdistro

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/docker/docker/pkg/homedir"
	"github.com/falcosecurity/driverkit/cmd"
	"github.com/falcosecurity/driverkit/pkg/driverbuilder"
	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
	"golang.org/x/net/context"
	"gopkg.in/ini.v1"

	"github.com/falcosecurity/falcoctl/internal/utils"
	drivertype "github.com/falcosecurity/falcoctl/pkg/driver/type"
	"github.com/falcosecurity/falcoctl/pkg/output"
)

const (
	kernelSrcDownloadFolder = "kernel-sources"
	// UndeterminedDistro is the string used for the generic distro object returned when we cannot determine the distro.
	UndeterminedDistro = "undetermined"
)

var (
	distros  = map[string]Distro{}
	hostRoot = string(os.PathSeparator)
	// ErrUnsupported is the error returned when the target distro is not supported.
	ErrUnsupported = errors.New("failed to determine distro")
	// ErrAlreadyPresent is the error returned when a driver is already present on filesystem.
	ErrAlreadyPresent = errors.New("driver already present")
)

// Distro is the common interface used by distro-specific implementations.
// Most of the distro-specific only partially override the default `generic` implementation.
type Distro interface {
	init(kr kernelrelease.KernelRelease, id string, cfg *ini.File) error    // private
	FixupKernel(kr kernelrelease.KernelRelease) kernelrelease.KernelRelease // private
	customizeBuild(ctx context.Context, printer *output.Printer, driverType drivertype.DriverType,
		kr kernelrelease.KernelRelease) (map[string]string, error)
	PreferredDriver(kr kernelrelease.KernelRelease, allowedDriverTypes []drivertype.DriverType) drivertype.DriverType
	fmt.Stringer
}

type checker interface {
	check() bool // private
}

// Discover tries to fetch the correct Distro by looking at /etc/os-release or
// by cycling on all supported distros and checking them one by one.
//
//nolint:gocritic // the method shall not be able to modify kr
func Discover(kr kernelrelease.KernelRelease, hostroot string) (Distro, error) {
	// Implicitly store hostroot to a package local variable
	// to avoid passing it in other APIs
	hostRoot = hostroot

	distro, err := getOSReleaseDistro(&kr)
	if err == nil {
		return distro, nil
	}

	// Fallback to check any distro checker
	for id, d := range distros {
		dd, ok := d.(checker)
		if ok && dd.check() {
			err = d.init(kr, id, nil)
			return d, err
		}
	}

	// Return a generic distro to try the build
	distro = &generic{}
	if err = distro.init(kr, UndeterminedDistro, nil); err != nil {
		return nil, err
	}
	return distro, ErrUnsupported
}

func getOSReleaseDistro(kr *kernelrelease.KernelRelease) (Distro, error) {
	cfg, err := ini.Load(hostRoot + "/etc/os-release")
	if err != nil {
		return nil, err
	}
	idKey, err := cfg.Section("").GetKey("ID")
	if err != nil {
		return nil, err
	}
	id := strings.ToLower(idKey.String())

	// Overwrite the OS_ID if /etc/VERSION file is present.
	// Not sure if there is a better way to detect minikube.
	dd := distros["minikube"].(checker)
	if dd.check() {
		id = "minikube"
	}

	distro, exist := distros[id]
	if !exist {
		distro = &generic{}
	}
	if err = distro.init(*kr, id, cfg); err != nil {
		return nil, err
	}
	return distro, nil
}

func toURL(repo, driverVer, fileName, arch string) string {
	return fmt.Sprintf("%s/%s/%s/%s", repo, url.QueryEscape(driverVer), arch, fileName)
}

func toLocalPath(driverVer, fileName, arch string) string {
	return fmt.Sprintf("%s/.falco/%s/%s/%s", homedir.Get(), driverVer, arch, fileName)
}

func toFilename(d Distro, kr *kernelrelease.KernelRelease, driverName string, driverType drivertype.DriverType) string {
	// Fixup kernel information before attempting to download
	fixedKR := d.FixupKernel(*kr)
	return fmt.Sprintf("%s_%s_%s_%s%s", driverName, d, fixedKR.String(), fixedKR.KernelVersion, driverType.Extension())
}

// copyDataToLocalPath will copy a src Reader to a destination file, creating it and its paths if needed.
// Moreover, it will also take care of closing the reader.
func copyDataToLocalPath(destination string, src io.ReadCloser) error {
	defer src.Close()
	err := os.MkdirAll(filepath.Dir(destination), 0o750)
	if err != nil {
		return err
	}
	out, err := os.Create(filepath.Clean(destination))
	if err == nil {
		defer out.Close()
		_, err = io.Copy(out, src)
	}
	return err
}

// Build will try to build the desired driver for the specified distro and kernel release.
//
//nolint:gocritic // the method shall not be able to modify kr
func Build(ctx context.Context,
	d Distro,
	printer *output.Printer,
	kr kernelrelease.KernelRelease,
	driverName string,
	driverType drivertype.DriverType,
	driverVer string,
	downloadHeaders bool,
) (string, error) {
	printer.Logger.Info("Trying to compile the requested driver")
	driverFileName := toFilename(d, &kr, driverName, driverType)
	destPath := toLocalPath(driverVer, driverFileName, kr.Architecture.ToNonDeb())
	if exist, _ := utils.FileExists(destPath); exist {
		return destPath, ErrAlreadyPresent
	}

	env, err := d.customizeBuild(ctx, printer, driverType, kr)
	if err != nil {
		return "", err
	}

	ro, err := getDKRootOptions(d, kr, driverType, driverVer, driverName, destPath)
	if err != nil {
		return "", err
	}

	// Disable automatic kernel headers fetching
	// if customizeBuild already retrieved kernel headers for us
	// (and has set the KernelDirEnv key)
	if _, ok := env[drivertype.KernelDirEnv]; ok {
		downloadHeaders = false
	}
	srcPath := fmt.Sprintf("/usr/src/%s-%s", driverName, driverVer)
	err = driverbuilder.NewLocalBuildProcessor(true, downloadHeaders, true, srcPath, env, 1000).Start(ro.ToBuild(printer))
	return destPath, err
}

//nolint:gocritic // the method shall not be able to modify kr
func getDKRootOptions(d Distro,
	kr kernelrelease.KernelRelease,
	driverType drivertype.DriverType,
	driverVer,
	driverName,
	destPath string,
) (*cmd.RootOptions, error) {
	ro, err := cmd.NewRootOptions()
	if err != nil {
		return nil, err
	}
	ro.Architecture = kr.Architecture.String()
	ro.DriverVersion = driverVer
	// We pass just the fixed kernelversion down to driverkit.
	// it is only used by ubuntu builder,
	// all the other builders do not use the kernelversion field.
	fixedKr := d.FixupKernel(kr)
	ro.KernelVersion = fixedKr.KernelVersion
	ro.ModuleDriverName = driverName
	ro.ModuleDeviceName = driverName
	ro.KernelRelease = kr.String()
	ro.Target = d.String()
	ro.Output = driverType.ToOutput(destPath)
	// This should never happen since kmod implements ToOutput; the only case this can happen is if a Build is requested
	// for modern-bpf driver type, but "install" cmd is smart enough to avoid that situation by using HasArtifacts()
	// method.
	if !ro.Output.HasOutputs() {
		return nil, errors.New("build on non-artifacts driver attempted")
	}
	return ro, nil
}

// Download will try to download drivers for a distro trying specified repos.
//
//nolint:gocritic // the method shall not be able to modify kr
func Download(ctx context.Context,
	d Distro,
	printer *output.Printer,
	kr kernelrelease.KernelRelease,
	driverName string,
	driverType drivertype.DriverType,
	driverVer string, repos []string,
	httpHeaders string,
) (string, error) {
	driverFileName := toFilename(d, &kr, driverName, driverType)
	// Skip if existent
	destination := toLocalPath(driverVer, driverFileName, kr.Architecture.ToNonDeb())
	if exist, _ := utils.FileExists(destination); exist {
		return destination, ErrAlreadyPresent
	}

	// Try to download from any specified repository,
	// stopping at first successful http GET.
	for _, repo := range repos {
		driverURL := toURL(repo, driverVer, driverFileName, kr.Architecture.ToNonDeb())
		printer.Logger.Info("Trying to download a driver.", printer.Logger.Args("url", driverURL))

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, driverURL, nil)
		if err != nil {
			printer.Logger.Warn("Error creating http request.", printer.Logger.Args("err", err))
			continue
		}
		if httpHeaders != "" {
			header := http.Header{}
			for _, h := range strings.Split(httpHeaders, ",") {
				key, value := func() (string, string) {
					x := strings.Split(h, ":")
					return x[0], x[1]
				}()
				header.Add(key, value)
			}
			req.Header = header
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil || resp.StatusCode != 200 {
			if err == nil {
				_ = resp.Body.Close()
				printer.Logger.Warn("Non-200 response from url.", printer.Logger.Args("code", resp.StatusCode))
			} else {
				printer.Logger.Warn("Error GETting url.", printer.Logger.Args("err", err))
			}
			continue
		}
		return destination, copyDataToLocalPath(destination, resp.Body)
	}
	return destination, fmt.Errorf("unable to find a prebuilt driver")
}
