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
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/falcosecurity/falcoctl/internal/version"
	"github.com/falcosecurity/falcoctl/pkg/options"
	"github.com/falcosecurity/falcoctl/pkg/output"
)

// New instantiates the root command and initializes the tree of commands.
func New(ctx context.Context, opt *options.CommonOptions) *cobra.Command {
	rootCmd := &cobra.Command{
		Use:               "falcoctl",
		Short:             "The control tool for running Falco in Kubernetes",
		DisableAutoGenTag: true,
	}

	// Global flags
	opt.AddFlags(rootCmd.PersistentFlags())

	// Commands
	rootCmd.AddCommand(NewTLSCmd())
	rootCmd.AddCommand(version.NewVersionCmd(opt))
	rootCmd.AddCommand(NewRegistryCmd(ctx, opt))
	rootCmd.AddCommand(NewIndexCmd(ctx, opt))
	rootCmd.AddCommand(NewArtifactCmd(ctx, opt))

	return rootCmd
}

// Execute creates the root command and runs it.
func Execute() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL)

	// If the ctx is marked as done then we reset the signals.
	go func() {
		<-ctx.Done()
		fmt.Printf("\nreceived signal, terminating...\n")
		stop()
	}()

	opt := options.NewOptions()
	cmd := New(ctx, opt)
	// we do not log the error here since we expect that each subcommand
	// handles the errors by itself.
	output.ExitOnErr(cmd.Execute())
}
