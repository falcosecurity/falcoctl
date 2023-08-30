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

	"github.com/spf13/cobra"

	"github.com/falcosecurity/falcoctl/cmd/artifact"
	"github.com/falcosecurity/falcoctl/cmd/index"
	"github.com/falcosecurity/falcoctl/cmd/registry"
	"github.com/falcosecurity/falcoctl/cmd/tls"
	"github.com/falcosecurity/falcoctl/cmd/version"
	"github.com/falcosecurity/falcoctl/pkg/options"
	"github.com/falcosecurity/falcoctl/pkg/output"
)

const (
	longRootCmd = `
     __       _                _   _ 
    / _| __ _| | ___ ___   ___| |_| |
   | |_ / _  | |/ __/ _ \ / __| __| |
   |  _| (_| | | (_| (_) | (__| |_| |
   |_|  \__,_|_|\___\___/ \___|\__|_|
									 
	
The official CLI tool for working with Falco and its ecosystem components
`
)

// New instantiates the root command and initializes the tree of commands.
func New(ctx context.Context, opt *options.Common) *cobra.Command {
	rootCmd := &cobra.Command{
		Use:               "falcoctl",
		Short:             "The official CLI tool for working with Falco and its ecosystem components",
		Long:              longRootCmd,
		DisableAutoGenTag: true,
	}

	// Global flags
	opt.AddFlags(rootCmd.PersistentFlags())

	// Commands
	rootCmd.AddCommand(tls.NewTLSCmd())
	rootCmd.AddCommand(version.NewVersionCmd(opt))
	rootCmd.AddCommand(registry.NewRegistryCmd(ctx, opt))
	rootCmd.AddCommand(index.NewIndexCmd(ctx, opt))
	rootCmd.AddCommand(artifact.NewArtifactCmd(ctx, opt))

	return rootCmd
}

// Execute configures the signal handlers and runs the command.
func Execute(cmd *cobra.Command, printer *output.Printer) error {
	// we do not log the error here since we expect that each subcommand
	// handles the errors by itself.
	err := cmd.Execute()
	printer.CheckErr(err)
	return err
}
