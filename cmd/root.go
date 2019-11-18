/*
Copyright © 2019 The Falco Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package cmd

import (
	"strings"

	"k8s.io/cli-runtime/pkg/genericclioptions"

	"github.com/falcosecurity/falcoctl/pkg/kubernetes/factory"
	"github.com/kris-nova/logger"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// RootOptions represents the base command options
type RootOptions struct {
	configFlags *genericclioptions.ConfigFlags

	genericclioptions.IOStreams

	fabulous bool
}

// Validate validates the base command options
func (o RootOptions) Validate(c *cobra.Command, args []string) error {
	return nil
}

// NewRootOptions instantiates the base command options
func NewRootOptions(streams genericclioptions.IOStreams) CommandOptions {
	return &RootOptions{
		configFlags: genericclioptions.NewConfigFlags(false),
		IOStreams:   streams,
	}
}

// NewRootCommand creates the command
func NewRootCommand(streams genericclioptions.IOStreams) *cobra.Command {
	o := NewRootOptions(streams).(*RootOptions)

	cmd := &cobra.Command{
		Use:                   "falcoctl",
		DisableFlagsInUseLine: true,
		Short:                 "The main control tool for Falco",
		Long:                  `The main control tool for running Falco in Kubernetes, ...`,
		PersistentPreRun: func(c *cobra.Command, args []string) {
			// Set destination for usage and error messages
			c.SetOutput(streams.ErrOut)
			// Be fabulous
			if o.fabulous {
				logger.Fabulous = true
				logger.Color = false
			}
		},
		Run: func(c *cobra.Command, args []string) {
			cobra.NoArgs(c, args)
			c.Help()
		},
	}

	cmd.PersistentFlags().BoolVarP(&o.fabulous, "fab", "f", o.fabulous, "Enable rainbow logs")
	cmd.PersistentFlags().IntVarP(&logger.Level, "verbose", "v", 3, "Verbosity 0 (off) 4 (most)")

	flags := cmd.Flags()
	o.configFlags.AddFlags(flags)

	matchVersionFlags := factory.NewMatchVersionFlags(o.configFlags)
	matchVersionFlags.AddFlags(flags)
	f := factory.NewFactory(matchVersionFlags)

	viper.AutomaticEnv()
	viper.SetEnvPrefix("falcoctl")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))

	cmd.AddCommand(NewInstallCommand(streams, f))
	cmd.AddCommand(NewDeleteCommand(streams, f))
	cmd.AddCommand(NewConvertCommand(streams))

	return cmd
}
