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

	"github.com/kris-nova/logger"
	"github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// New creates the faloctl root command
func New(streams genericclioptions.IOStreams) *cobra.Command {
	configOptions := NewConfigOptions()
	cobra.OnInitialize(func() {
		initConfig(configOptions)
	})

	cmd := &cobra.Command{
		Use:                   "falcoctl",
		DisableFlagsInUseLine: true,
		Short:                 "The main control tool for Falco",
		Long:                  `The main control tool for running Falco in Kubernetes, ...`,
		PersistentPreRun: func(c *cobra.Command, args []string) {
			// Set destination for usage and error messages
			c.SetOutput(streams.ErrOut)
			// Be fabulous
			if configOptions.Fabulous {
				logger.Fabulous = true
				logger.Color = false
			}
			logger.Level = configOptions.Verbose
		},
		Run: func(c *cobra.Command, args []string) {
			cobra.NoArgs(c, args)
			c.Help()
		},
	}

	cmd.PersistentFlags().StringVarP(&configOptions.ConfigFile, "config", "c", configOptions.ConfigFile, "config file path (default $HOME/.falcoctl.yaml if exists)")
	cmd.PersistentFlags().BoolVarP(&configOptions.Fabulous, "fab", "f", configOptions.Fabulous, "enable rainbow logs")
	cmd.PersistentFlags().IntVarP(&configOptions.Verbose, "verbose", "v", configOptions.Verbose, "verbosity 0 (off) 4 (most)")

	cmd.AddCommand(Install(streams))
	cmd.AddCommand(Delete(streams))
	cmd.AddCommand(Convert(streams))

	return cmd
}

// initConfig reads in config file and ENV variables if set.
func initConfig(configOptions *ConfigOptions) {
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
		}

		viper.AddConfigPath(home)
		viper.SetConfigName(".falcoctl")
	}

	viper.AutomaticEnv()
	viper.SetEnvPrefix("falcoctl")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

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
		}
	}
}
