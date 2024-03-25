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
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/docker/docker/pkg/homedir"
	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
	"golang.org/x/net/context"
	"gopkg.in/ini.v1"

	"github.com/falcosecurity/falcoctl/internal/utils"
	drivertype "github.com/falcosecurity/falcoctl/pkg/driver/type"
	"github.com/falcosecurity/falcoctl/pkg/output"
)

const (
	kernelDirEnv            = "KERNELDIR"
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
		return nil, nil
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
) (string, error) {
	driverFileName := toFilename(d, &kr, driverName, driverType)
	destination := toLocalPath(driverVer, driverFileName, kr.Architecture.ToNonDeb())
	if exist, _ := utils.FileExists(destination); exist {
		return destination, ErrAlreadyPresent
	}

	env, err := d.customizeBuild(ctx, printer, driverType, kr)
	if err != nil {
		return "", err
	}
	path, err := driverType.Build(ctx, printer, kr, driverName, driverVer, env)
	if err != nil {
		return "", err
	}
	// Copy the path to the expected location.
	// NOTE: for kmod, this is not useful since the driver will
	// be loaded directly by dkms.
	printer.Logger.Info("Copying built driver to its destination.", printer.Logger.Args("src", path, "dst", destination))
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return "", err
	}
	return destination, copyDataToLocalPath(destination, f)
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
		url := toURL(repo, driverVer, driverFileName, kr.Architecture.ToNonDeb())
		printer.Logger.Info("Trying to download a driver.", printer.Logger.Args("url", url))

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
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

func customizeDownloadKernelSrcBuild(printer *output.Printer, kr *kernelrelease.KernelRelease) error {
	printer.Logger.Info("Configuring kernel.")
	if kr.Extraversion != "" {
		err := utils.ReplaceLineInFile(".config", "LOCALVERSION=", "LOCALVERSION="+kr.Extraversion, 1)
		if err != nil {
			return err
		}
	}
	_, err := exec.Command("bash", "-c", "make olddefconfig").Output()
	if err == nil {
		_, err = exec.Command("bash", "-c", "make modules_prepare").Output()
	}
	return err
}

func getKernelConfig(printer *output.Printer, kr *kernelrelease.KernelRelease) (string, error) {
	bootConfig := fmt.Sprintf("/boot/config-%s", kr.String())
	hrBootConfig := fmt.Sprintf("%s%s", hostRoot, bootConfig)
	ostreeConfig := fmt.Sprintf("/usr/lib/ostree-boot/config-%s", kr.String())
	hrostreeConfig := fmt.Sprintf("%s%s", hostRoot, ostreeConfig)
	libModulesConfig := fmt.Sprintf("/lib/modules/%s/config", kr.String())

	toBeChecked := []string{
		"/proc/config.gz",
		bootConfig,
		hrBootConfig,
		ostreeConfig,
		hrostreeConfig,
		libModulesConfig,
	}

	for _, path := range toBeChecked {
		if exist, _ := utils.FileExists(path); exist {
			printer.Logger.Info("Found kernel config.", printer.Logger.Args("path", path))
			return path, nil
		}
	}
	return "", fmt.Errorf("cannot find kernel config")
}

func downloadKernelSrc(ctx context.Context,
	printer *output.Printer,
	kr *kernelrelease.KernelRelease,
	url string,
	stripComponents int,
) (map[string]string, error) {
	env := make(map[string]string)

	printer.Logger.Info("Downloading kernel sources.", printer.Logger.Args("url", url))
	err := os.MkdirAll("/tmp/kernel", 0o750)
	if err != nil {
		return env, err
	}
	tempDir, err := os.MkdirTemp("/tmp/kernel", "")
	if err != nil {
		return env, err
	}

	// Download the url
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return env, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return env, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return env, fmt.Errorf("non-200 http GET status code")
	}

	printer.Logger.Info("Extracting kernel sources.")

	fullKernelDir := filepath.Join(tempDir, kernelSrcDownloadFolder)

	err = os.Mkdir(fullKernelDir, 0o750)
	if err != nil {
		return env, err
	}

	_, err = utils.ExtractTarGz(ctx, resp.Body, fullKernelDir, stripComponents)
	if err != nil {
		return env, err
	}

	kernelConfigPath, err := getKernelConfig(printer, kr)
	if err != nil {
		return nil, err
	}
	dest, err := os.Create(".config")
	if err != nil {
		return nil, err
	}
	f, err := os.Open(filepath.Clean(kernelConfigPath))
	if err != nil {
		return nil, err
	}
	var src io.ReadCloser
	if strings.HasSuffix(kernelConfigPath, ".gz") {
		src, err = gzip.NewReader(f)
		if err != nil {
			return env, err
		}
	} else {
		src = f
	}
	defer src.Close()

	fStat, err := f.Stat()
	if err != nil {
		return nil, err
	}
	_, err = io.CopyN(dest, src, fStat.Size())
	if err != nil {
		return nil, err
	}
	env[kernelDirEnv] = fullKernelDir
	return env, nil
}
