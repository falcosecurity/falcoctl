/*
Copyright © 2019 The Falco Authors.

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
	"github.com/kris-nova/logger"
	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
)

// RuleOptions represents the `install tls` command options
type RuleOptions struct {
	genericclioptions.IOStreams
}

// Validate validates the `install probe` command options
func (o RuleOptions) Validate(c *cobra.Command, args []string) error {
	return nil
}

// NewRuleOptions instantiates the `install rule` command options
func NewRuleOptions(streams genericclioptions.IOStreams) CommandOptions {
	o := &RuleOptions{
		IOStreams: streams,
	}
	return o
}

// InstallRule creates the `install rule` command
func InstallRule(streams genericclioptions.IOStreams) *cobra.Command {
	// todo > uncomment me when implementing this command
	// o := NewRuleOptions(streams).(*RuleOptions)

	cmd := &cobra.Command{
		Use:                   "rule",
		DisableFlagsInUseLine: true,
		Short:                 "Install Falco rules.",
		Long:                  `Install Falco rules`,
		RunE: func(cmd *cobra.Command, args []string) error {
			logger.Info("to be implemented")

			return nil
		},
	}

	return cmd
}
