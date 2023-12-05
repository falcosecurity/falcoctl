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
	"bytes"
	"strings"

	"github.com/pterm/pterm"
	"github.com/spf13/cobra"
	"golang.org/x/net/context"

	"github.com/falcosecurity/falcoctl/pkg/options"
)

type driverCleanupOptions struct {
	*options.Common
	*options.Driver
}

// NewDriverCleanupCmd cleans a driver up.
func NewDriverCleanupCmd(ctx context.Context, opt *options.Common, driver *options.Driver) *cobra.Command {
	o := driverCleanupOptions{
		Common: opt,
		Driver: driver,
	}

	cmd := &cobra.Command{
		Use:                   "cleanup [flags]",
		DisableFlagsInUseLine: true,
		Short:                 "[Preview] Cleanup a driver",
		Long: `[Preview] Cleans a driver up, eg for kmod, by removing it from dkms.
** This command is in preview and under development. **`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return o.RunDriverCleanup(ctx)
		},
	}
	return cmd
}

func (o *driverCleanupOptions) RunDriverCleanup(_ context.Context) error {
	o.Printer.Logger.Info("Running falcoctl driver cleanup", o.Printer.Logger.Args(
		"driver type", o.Driver.Type,
		"driver name", o.Driver.Name))
	var buf bytes.Buffer
	if !o.Printer.DisableStyling {
		o.Printer.Spinner, _ = o.Printer.Spinner.Start("Cleaning up existing drivers")
	}
	err := o.Driver.Type.Cleanup(o.Printer.WithWriter(&buf), o.Driver.Name)
	if o.Printer.Spinner != nil {
		_ = o.Printer.Spinner.Stop()
	}
	if o.Printer.Logger.Formatter == pterm.LogFormatterJSON {
		// Only print formatted text if we are formatting to json
		out := strings.ReplaceAll(buf.String(), "\n", ";")
		o.Printer.Logger.Info("Driver build", o.Printer.Logger.Args("output", out))
	} else {
		// Print much more readable output as-is
		o.Printer.DefaultText.Print(buf.String())
	}
	return err
}
