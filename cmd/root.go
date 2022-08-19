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
	"os"
	"os/signal"
	"syscall"

	logger "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/falcosecurity/falcoctl/pkg/options"
	"github.com/falcosecurity/falcoctl/pkg/version"
)

const (
	defaultRepoPath = ".falcoctl"
	defaultRepoFile = "sources.yaml"
)

func init() {
	logger.SetFormatter(&logger.TextFormatter{
		ForceColors:            true,
		DisableLevelTruncation: false,
		DisableTimestamp:       true,
	})
}

// New instantiates the root command.
func New() *cobra.Command {
	opt := options.NewOptions()

	rootCmd := &cobra.Command{
		Use:               "falcoctl",
		Short:             "The control tool for running Falco in Kubernetes",
		DisableAutoGenTag: true,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			// Initializing the options. Subcommands can overwrite configs for the options
			// by calling the initialize function.
			opt.Initialize()
		},
		Run: func(c *cobra.Command, args []string) {
			c.Help()
		},
	}

	// Global flags
	opt.AddFlags(rootCmd.Flags())

	// Commands
	rootCmd.AddCommand(NewDeleteCmd(nil))
	rootCmd.AddCommand(NewInstallCmd())
	rootCmd.AddCommand(NewSearchCmd(NewSearchOptions()))
	rootCmd.AddCommand(NewRepoCmd(NewRepoOptions()))
	rootCmd.AddCommand(NewListCmd(NewListOptions()))
	rootCmd.AddCommand(version.NewVersionCmd(opt))

	return rootCmd
}

// Execute creates the root command and runs it.
func Execute() {
	ctx := WithSignals(context.Background())
	if err := New().ExecuteContext(ctx); err != nil {
		logger.WithError(err).Fatal("error executing falcoctl")
	}
}

// WithSignals returns a copy of ctx with a new Done channel.
// The returned context's Done channel is closed when a SIGKILL or SIGTERM signal is received.
func WithSignals(ctx context.Context) context.Context {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	ctx, cancel := context.WithCancel(ctx)
	go func() {
		defer cancel()
		select {
		case <-ctx.Done():
			return
		case s := <-sigCh:
			switch s {
			case os.Interrupt:
				logger.Infof("received SIGINT")
			case syscall.SIGTERM:
				logger.Infof("received SIGTERM")
			}
			return
		}
	}()
	return ctx
}

// initLogger configures the logger
func initLogger(logLevel string) {
	lvl, err := logger.ParseLevel(logLevel)
	if err != nil {
		logger.Fatal(err)
	}
	logger.SetLevel(lvl)
}
