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

	"github.com/spf13/cobra"

	drivercleanup "github.com/falcosecurity/falcoctl/cmd/driver/cleanup"
	driverconfig "github.com/falcosecurity/falcoctl/cmd/driver/config"
	driverinstall "github.com/falcosecurity/falcoctl/cmd/driver/install"
	driverprintenv "github.com/falcosecurity/falcoctl/cmd/driver/printenv"
	"github.com/falcosecurity/falcoctl/internal/config"
	commonoptions "github.com/falcosecurity/falcoctl/pkg/options"
)

// NewDriverCmd returns the driver command.
func NewDriverCmd(ctx context.Context, opt *commonoptions.Common) *cobra.Command {
	cmd := &cobra.Command{
		Use:                   "driver",
		DisableFlagsInUseLine: true,
		Short:                 "Interact with falcosecurity driver",
		Long:                  "Interact with falcosecurity driver",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			opt.Initialize()
			return config.Load(opt.ConfigFile)
		},
	}

	cmd.AddCommand(driverinstall.NewDriverInstallCmd(ctx, opt))
	cmd.AddCommand(driverconfig.NewDriverConfigCmd(ctx, opt))
	cmd.AddCommand(drivercleanup.NewDriverCleanupCmd(ctx, opt))
	cmd.AddCommand(driverprintenv.NewDriverPrintenvCmd(ctx, opt))
	return cmd
}
