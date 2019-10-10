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
	"os"

	kubernetesfalc "github.com/falcosecurity/falcoctl/pkg/kubernetes"
	"github.com/falcosecurity/falcoctl/pkg/kubernetes/factory"
	"github.com/kris-nova/logger"
	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
)

// FalcoInstallOptions represents the `install falco` command options
type FalcoInstallOptions struct {
	genericclioptions.IOStreams

	daemonSetName string
}

// Validate validates the `install falco` command options
func (o FalcoInstallOptions) Validate(c *cobra.Command, args []string) error {
	return nil
}

// NewFalcoInstallOptions instantiates the `install falco` command options
func NewFalcoInstallOptions(streams genericclioptions.IOStreams) CommandOptions {
	return &FalcoInstallOptions{
		IOStreams: streams,
	}
}

// NewFalcoInstallCommand creates the `install falco` command
func NewFalcoInstallCommand(streams genericclioptions.IOStreams, f factory.Factory) *cobra.Command {
	o := NewFalcoInstallOptions(streams).(*FalcoInstallOptions)

	cmd := &cobra.Command{
		Use:                   "falco",
		DisableFlagsInUseLine: true,
		Short:                 "Install Falco in Kubernetes",
		Long:                  `Deploy Falco to Kubernetes`,
		Run: func(cmd *cobra.Command, args []string) {
			// todo > pass daemonset name using o.daemonSetName
			installer, err := kubernetesfalc.NewFalcoInstaller(f)
			if err != nil {
				logger.Critical("Fatal error: %v", err)
				os.Exit(1)
			}
			err = installer.Install()
			if err != nil {
				logger.Critical("Fatal error: %v", err)
				os.Exit(1)
			}
		},
	}

	cmd.Flags().StringVarP(&o.daemonSetName, "daemonset-name", "D", o.daemonSetName, "Set the name to use with the Falco DaemonSet")

	return cmd
}
