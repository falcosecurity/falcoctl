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

//go:build linux

// Package driver implements the driver related cmd line interface.
package driver

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/blang/semver"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	drivercleanup "github.com/falcosecurity/falcoctl/cmd/driver/cleanup"
	driverconfig "github.com/falcosecurity/falcoctl/cmd/driver/config"
	driverinstall "github.com/falcosecurity/falcoctl/cmd/driver/install"
	driverprintenv "github.com/falcosecurity/falcoctl/cmd/driver/printenv"
	"github.com/falcosecurity/falcoctl/internal/config"
	driverdistro "github.com/falcosecurity/falcoctl/pkg/driver/distro"
	driverkernel "github.com/falcosecurity/falcoctl/pkg/driver/kernel"
	drivertype "github.com/falcosecurity/falcoctl/pkg/driver/type"
	"github.com/falcosecurity/falcoctl/pkg/options"
)

// NewDriverCmd returns the driver command.
func NewDriverCmd(ctx context.Context, opt *options.Common) *cobra.Command {
	driver := &options.Driver{}
	driverTypes := options.NewDriverTypes()

	cmd := &cobra.Command{
		Use:                   "driver",
		DisableFlagsInUseLine: true,
		Short:                 "[Preview] Interact with falcosecurity driver",
		Long: `[Preview] Interact with falcosecurity driver.
** This command is in preview and under development. **`,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			opt.Initialize()
			if err := config.Load(opt.ConfigFile); err != nil {
				return err
			}

			// Override "version" flag with viper config if not set by user.
			f := cmd.Flags().Lookup("version")
			if f == nil {
				// should never happen
				return fmt.Errorf("unable to retrieve flag version")
			} else if !f.Changed && viper.IsSet(config.DriverVersionKey) {
				val := viper.Get(config.DriverVersionKey)
				if err := cmd.Flags().Set(f.Name, fmt.Sprintf("%v", val)); err != nil {
					return fmt.Errorf("unable to overwrite \"version\" flag: %w", err)
				}
			}

			// Override "repo" flag with viper config if not set by user.
			f = cmd.Flags().Lookup("repo")
			if f == nil {
				// should never happen
				return fmt.Errorf("unable to retrieve flag repo")
			} else if !f.Changed && viper.IsSet(config.DriverReposKey) {
				val, err := config.DriverRepos()
				if err != nil {
					return err
				}
				if err := cmd.Flags().Set(f.Name, strings.Join(val, ",")); err != nil {
					return fmt.Errorf("unable to overwrite \"repo\" flag: %w", err)
				}
			}

			// Override "name" flag with viper config if not set by user.
			f = cmd.Flags().Lookup("name")
			if f == nil {
				// should never happen
				return fmt.Errorf("unable to retrieve flag name")
			} else if !f.Changed && viper.IsSet(config.DriverNameKey) {
				val := viper.Get(config.DriverNameKey)
				if err := cmd.Flags().Set(f.Name, fmt.Sprintf("%v", val)); err != nil {
					return fmt.Errorf("unable to overwrite \"name\" flag: %w", err)
				}
			}

			// Override "host-root" flag with viper config if not set by user.
			f = cmd.Flags().Lookup("host-root")
			if f == nil {
				// should never happen
				return fmt.Errorf("unable to retrieve flag host-root")
			} else if !f.Changed && viper.IsSet(config.DriverHostRootKey) {
				val := viper.Get(config.DriverHostRootKey)
				if err := cmd.Flags().Set(f.Name, fmt.Sprintf("%v", val)); err != nil {
					return fmt.Errorf("unable to overwrite \"host-root\" flag: %w", err)
				}
			}

			// Override "type" flag with viper config if not set by user.
			f = cmd.Flags().Lookup("type")
			if f == nil {
				// should never happen
				return fmt.Errorf("unable to retrieve flag type")
			} else if !f.Changed && viper.IsSet(config.DriverTypeKey) {
				val := viper.Get(config.DriverTypeKey)
				if err := cmd.Flags().Set(f.Name, fmt.Sprintf("%v", val)); err != nil {
					return fmt.Errorf("unable to overwrite \"type\" flag: %w", err)
				}
			}

			if driverTypes.String() != drivertype.TypeAuto {
				var err error
				// Ok driver type was enforced by the user
				driver.Type, err = drivertype.Parse(driverTypes.String())
				if err != nil {
					return err
				}
			} else {
				// automatic logic
				info, err := driverkernel.FetchInfo("", "")
				if err != nil {
					return err
				}
				opt.Printer.Logger.Debug("Fetched kernel info", opt.Printer.Logger.Args(
					"arch", info.Architecture.ToNonDeb(),
					"kernel release", info.String(),
					"kernel version", info.KernelVersion))

				d, err := driverdistro.Discover(info, driver.HostRoot)
				if err != nil {
					if !errors.Is(err, driverdistro.ErrUnsupported) {
						return err
					}
					opt.Printer.Logger.Info("Detected an unsupported target system; falling back at generic logic.")
				}
				opt.Printer.Logger.Debug("Discovered distro", opt.Printer.Logger.Args("target", d))

				driver.Type = d.PreferredDriver(info)
				if driver.Type == nil {
					return fmt.Errorf("automatic driver selection failed")
				}
			}
			// If empty, try to load it automatically from /usr/src sub folders,
			// using the most recent (ie: the one with greatest semver) driver version.
			if driver.Version == "" {
				driver.Version = loadDriverVersion()
			}
			return driver.Validate()
		},
	}

	cmd.PersistentFlags().Var(driverTypes, "type", "Driver type to be used "+driverTypes.Allowed())
	cmd.PersistentFlags().StringVar(&driver.Version, "version", config.DefaultDriver.Version, "Driver version to be used.")
	cmd.PersistentFlags().StringSliceVar(&driver.Repos, "repo", config.DefaultDriver.Repos, "Driver repo to be used.")
	cmd.PersistentFlags().StringVar(&driver.Name, "name", config.DefaultDriver.Name, "Driver name to be used.")
	cmd.PersistentFlags().StringVar(&driver.HostRoot, "host-root", config.DefaultDriver.HostRoot, "Driver host root to be used.")

	cmd.AddCommand(driverinstall.NewDriverInstallCmd(ctx, opt, driver))
	cmd.AddCommand(driverconfig.NewDriverConfigCmd(ctx, opt, driver))
	cmd.AddCommand(drivercleanup.NewDriverCleanupCmd(ctx, opt, driver))
	cmd.AddCommand(driverprintenv.NewDriverPrintenvCmd(ctx, opt, driver))
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
