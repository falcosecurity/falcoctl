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

package drivercleanup

import (
	"github.com/spf13/cobra"
	"golang.org/x/net/context"

	"github.com/falcosecurity/falcoctl/internal/config"
	"github.com/falcosecurity/falcoctl/pkg/options"
)

type driverCleanupOptions struct {
	*options.Common
}

// NewDriverCleanupCmd cleans a driver up.
func NewDriverCleanupCmd(ctx context.Context, opt *options.Common) *cobra.Command {
	o := driverCleanupOptions{
		Common: opt,
	}

	cmd := &cobra.Command{
		Use:                   "cleanup [flags]",
		DisableFlagsInUseLine: true,
		Short:                 "Cleanup a driver",
		Long:                  "Cleans a driver up, eg for kmod, by removing it from dkms.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return o.RunDriverCleanup(ctx)
		},
	}
	return cmd
}

func (o *driverCleanupOptions) RunDriverCleanup(_ context.Context) error {
	driver, err := config.Driverer()
	if err != nil {
		return err
	}
	o.Printer.Logger.Info("Running falcoctl driver cleanup", o.Printer.Logger.Args(
		"driver type", driver.Type,
		"driver name", driver.Name))
	return driver.Type.Cleanup(o.Printer, driver.Name)
}
