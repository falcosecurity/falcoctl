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

// RuleInstallOptions represents the `install tls` command options
type RuleInstallOptions struct {
	genericclioptions.IOStreams
	country string
	org     string
	name    string
	path    string
}

// Validate validates the `install probe` command options
func (o RuleInstallOptions) Validate(c *cobra.Command, args []string) error {
	return nil
}

// NewRuleInstallOptions instantiates the `install rule` command options
func NewRuleInstallOptions(streams genericclioptions.IOStreams) CommandOptions {
	o := &RuleInstallOptions{
		IOStreams: streams,
	}
	return o
}

// NewRuleInstallCommand creates the `install rule` command
func NewRuleInstallCommand(streams genericclioptions.IOStreams) *cobra.Command {
	o := NewRuleInstallOptions(streams).(*RuleInstallOptions)

	cmd := &cobra.Command{
		Use:                   "rule",
		DisableFlagsInUseLine: true,
		Short:                 "Install Falco rules.",
		Long: `Install Falco rules`,
		RunE: func(cmd *cobra.Command, args []string) error {

			//
			//
			//
			//
			//
			//
			//

			logger.Debug(o.name)

			return nil
		},
	}

	return cmd
}
