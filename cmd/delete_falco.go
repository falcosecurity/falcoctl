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
	"k8s.io/cli-runtime/pkg/genericclioptions"

	"github.com/kris-nova/logger"
	"github.com/spf13/cobra"
)

// FalcoDeleteOptions represents the `delete falco` command options
type FalcoDeleteOptions struct {
}

// Validate validates the `delete falco` command options
func (o FalcoDeleteOptions) Validate(c *cobra.Command, args []string) error {
	return nil
}

// NewFalcoDeleteOptions instantiates the `delete falco` command options
func NewFalcoDeleteOptions() CommandOptions {
	return &FalcoDeleteOptions{}
}

// DeleteFalco creates the `delete falco` command
func DeleteFalco(streams genericclioptions.IOStreams) *cobra.Command {
	o := NewFalcoDeleteOptions().(*FalcoDeleteOptions)

	var clientGetter genericclioptions.RESTClientGetter
	cmd := &cobra.Command{
		Use:                   "falco",
		DisableFlagsInUseLine: true,
		Short:                 "Delete Falco from Kubernetes",
		Long:                  `Delete Falco from Kubernetes`,
		Run: func(cmd *cobra.Command, args []string) {
			logger.Info("to be implemented")
		},
	}

	return cmd
}
