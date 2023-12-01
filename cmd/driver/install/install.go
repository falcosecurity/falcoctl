// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2023 The Falco Authors
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

package driverinstall

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/blang/semver"
	"github.com/spf13/cobra"
	"golang.org/x/net/context"

	"github.com/falcosecurity/falcoctl/internal/config"
	driverdistro "github.com/falcosecurity/falcoctl/pkg/driver/distro"
	driverkernel "github.com/falcosecurity/falcoctl/pkg/driver/kernel"
	"github.com/falcosecurity/falcoctl/pkg/options"
)

type driverDownloadOptions struct {
	InsecureDownload bool
	HTTPTimeout      time.Duration
}

type driverInstallOptions struct {
	*options.Common
	Download            bool
	Compile             bool
	DriverKernelRelease string
	DriverKernelVersion string
	driverDownloadOptions
}

// NewDriverInstallCmd returns the driver install command.
func NewDriverInstallCmd(ctx context.Context, opt *options.Common) *cobra.Command {
	o := driverInstallOptions{
		Common: opt,
		// Defaults to downloading or building if needed
		Download: true,
		Compile:  true,
	}

	cmd := &cobra.Command{
		Use:                   "install [flags]",
		DisableFlagsInUseLine: true,
		Short:                 "[Preview] Install previously configured driver",
		Long: `[Preview] Install previously configured driver, either downloading it or attempting a build.
** This command is in preview and under development. **`,
		RunE: func(cmd *cobra.Command, args []string) error {
			driver, err := config.Driverer()
			if err != nil {
				return err
			}
			// If empty, try to load it automatically from /usr/src sub folders,
			// using the most recent (ie: the one with greatest semver) driver version.
			if driver.Version == "" {
				driver.Version = loadDriverVersion()
			}
			dest, err := o.RunDriverInstall(ctx, &driver)
			if dest != "" {
				// We don't care about errors at this stage
				// Fallback: try to load any available driver if leaving with an error.
				// It is only useful for kmod, as it will try to
				// modprobe a pre-existent version of the driver,
				// hoping it will be compatible.
				_ = driver.Type.Load(o.Printer, dest, err != nil)
			}
			return err
		},
	}

	cmd.Flags().BoolVar(&o.Download, "download", true, "Whether to enable download of prebuilt drivers")
	cmd.Flags().BoolVar(&o.Compile, "compile", true, "Whether to enable local compilation of drivers")
	cmd.Flags().StringVar(&o.DriverKernelRelease,
		"kernelrelease",
		"",
		"Specify the kernel release for which to download/build the driver in the same format used by 'uname -r' "+
			"(e.g. '6.1.0-10-cloud-amd64')")
	cmd.Flags().StringVar(&o.DriverKernelVersion,
		"kernelversion",
		"",
		"Specify the kernel version for which to download/build the driver in the same format used by 'uname -v' "+
			"(e.g. '#1 SMP PREEMPT_DYNAMIC Debian 6.1.38-2 (2023-07-27)')")
	cmd.Flags().BoolVar(&o.InsecureDownload, "http-insecure", false, "Whether you want to allow insecure downloads or not")
	cmd.Flags().DurationVar(&o.HTTPTimeout, "http-timeout", 60*time.Second, "Timeout for each http try")
	return cmd
}

func loadDriverVersion() string {
	isSet := false
	greatestVrs := semver.Version{}
	paths, _ := filepath.Glob("/usr/src/falco-*+driver")
	for _, path := range paths {
		drvVer := strings.TrimPrefix(filepath.Base(path), "falco-")
		sv, err := semver.Parse(drvVer)
		if err != nil {
			continue
		}
		if sv.GT(greatestVrs) {
			greatestVrs = sv
			isSet = true
		}
	}
	if isSet {
		return greatestVrs.String()
	}
	return ""
}

//nolint:gosec // this was an existent option in falco-driver-loader that we are porting.
func setDefaultHTTPClientOpts(downloadOptions driverDownloadOptions) {
	// Skip insecure verify
	if downloadOptions.InsecureDownload {
		http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	http.DefaultClient.Timeout = downloadOptions.HTTPTimeout
}

// RunDriverInstall implements the driver install command.
func (o *driverInstallOptions) RunDriverInstall(ctx context.Context, driver *config.Driver) (string, error) {
	kr, err := driverkernel.FetchInfo(o.DriverKernelRelease, o.DriverKernelVersion)
	if err != nil {
		return "", err
	}

	o.Printer.Logger.Info("Running falcoctl driver install", o.Printer.Logger.Args(
		"driver version", driver.Version,
		"driver type", driver.Type,
		"driver name", driver.Name,
		"compile", o.Compile,
		"download", o.Download,
		"arch", kr.Architecture.ToNonDeb(),
		"kernel release", kr.String(),
		"kernel version", kr.KernelVersion))

	if !driver.Type.HasArtifacts() {
		o.Printer.Logger.Info("No artifacts needed for the selected driver.")
		return "", nil
	}

	if !o.Download && !o.Compile {
		o.Printer.Logger.Info("Nothing to do: download and compile disabled.")
		return "", nil
	}

	d, err := driverdistro.Discover(kr, driver.HostRoot)
	if err != nil {
		if errors.Is(err, driverdistro.ErrUnsupported) && o.Compile {
			o.Download = false
			o.Printer.Logger.Info(
				"Detected an unsupported target system, please get in touch with the Falco community. Trying to compile anyway.")
		} else {
			return "", fmt.Errorf("detected an unsupported target system, please get in touch with the Falco community")
		}
	}
	o.Printer.Logger.Info("found distro", o.Printer.Logger.Args("target", d))

	err = driver.Type.Cleanup(o.Printer, driver.Name)
	if err != nil {
		return "", err
	}

	setDefaultHTTPClientOpts(o.driverDownloadOptions)

	var dest string
	if o.Download {
		dest, err = driverdistro.Download(ctx, d, o.Printer, kr, driver.Name, driver.Type, driver.Version, driver.Repos)
		if err == nil {
			return dest, nil
		}
		// Print the error but go on
		// attempting a build if requested
		o.Printer.Logger.Warn(err.Error())
	}

	if o.Compile {
		dest, err = driverdistro.Build(ctx, d, o.Printer, kr, driver.Name, driver.Type, driver.Version)
		if err == nil {
			return dest, nil
		}
		o.Printer.Logger.Warn(err.Error())
	}

	return driver.Name, fmt.Errorf("failed: %w", err)
}
