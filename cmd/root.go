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
	"os"
	"strings"

	"k8s.io/cli-runtime/pkg/genericclioptions"

	"github.com/falcosecurity/falcoctl/pkg/kubernetes/factory"
	"github.com/kris-nova/logger"
	"github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

var configOptions *ConfigOptions

// Start setups and starts the CLI.
func Start() {
	root := New()
	if err := root.Execute(); err != nil {
		logger.Critical("error executing falcoctl: %s", err)
		os.Exit(1)
	}
}

func init() {
	configOptions = NewConfigOptions()
	cobra.OnInitialize(initConfig)
}

// New creates the faloctl root command
func New() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:                   "falcoctl",
		DisableFlagsInUseLine: true,
		TraverseChildren:      true,
		Short:                 "The main control tool for Falco",
		Long:                  `The main control tool for running Falco in Kubernetes, ...`,
		Run: func(c *cobra.Command, args []string) {
			// Fallback to help
			c.Help()
		},
	}
	streams := genericclioptions.IOStreams{
		In:     os.Stdin,
		Out:    os.Stdout,
		ErrOut: os.Stderr,
	}
	// Set destination for usage and error messages
	rootCmd.SetOut(streams.Out)
	rootCmd.SetErr(streams.ErrOut)

	rootCmd.PersistentPreRun = func(c *cobra.Command, args []string) {
		// When a flag is not provided by the user,
		// fallback to one of (in order of precedence):
		// - ENV (with FALCOCTL_ prefix)
		// - config file (e.g. ~/.falcoctl.yaml)
		// - its default
		viper.BindPFlags(c.Flags())
		c.Flags().VisitAll(func(f *pflag.Flag) {
			if v := viper.GetString(f.Name); v != "" {
				c.Flags().Set(f.Name, v)
			}
		})

		// Be fabulous
		if configOptions.Fabulous {
			logger.Fabulous = true
			logger.Color = false
		}
		logger.Level = configOptions.Verbose
	}

	pflags := rootCmd.PersistentFlags()
	pflags.StringVar(&configOptions.ConfigFile, "config", configOptions.ConfigFile, "config file path (default $HOME/.falcoctl.yaml if exists)")
	pflags.BoolVarP(&configOptions.Fabulous, "fab", "f", configOptions.Fabulous, "enable rainbow logs")
	pflags.IntVarP(&configOptions.Verbose, "verbose", "v", configOptions.Verbose, "verbosity 0 (off) 4 (most)")

	rootCmd.AddCommand(Install(streams))
	rootCmd.AddCommand(Delete(streams))
	rootCmd.AddCommand(Convert(streams))

	return rootCmd
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if errs := configOptions.Validate(); errs != nil {
		for _, err := range errs {
			logger.Critical("error validating config options: %s", err)
		}
		os.Exit(1)
	}
	if configOptions.ConfigFile != "" {
		viper.SetConfigFile(configOptions.ConfigFile)
	} else {
		// Find home directory.
		home, err := homedir.Dir()
		if err != nil {
			logger.Critical("error getting the home directory: %s", err)
			os.Exit(1)
		}

		viper.AddConfigPath(home)
		viper.SetConfigName(".falcoctl")
	}

	viper.AutomaticEnv()
	viper.SetEnvPrefix("falcoctl")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		logger.Info("using config file: %s", viper.ConfigFileUsed())
	} else {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Config file not found, ignore ...
			logger.Debug("running without a configuration file")
		} else {
			// Config file was found but another error was produced
			logger.Critical("error running with config file: %s", err)
			os.Exit(1)
		}
	}
}

func initKubeFlags(flags *pflag.FlagSet) genericclioptions.RESTClientGetter {
	configFlags := genericclioptions.NewConfigFlags(false)
	configFlags.AddFlags(flags)

	matchVersionFlags := factory.MatchVersion(configFlags)
	matchVersionFlags.AddFlags(flags)
	return matchVersionFlags
}
