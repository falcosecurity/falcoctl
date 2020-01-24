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
	"github.com/falcosecurity/falcoctl/pkg/kubernetes/factory"
	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
)

// DeleteOptions represents the `delete` command options
type DeleteOptions struct {
	genericclioptions.IOStreams
}

// Validate validates the `delete` command options
func (o DeleteOptions) Validate(c *cobra.Command, args []string) error {
	return nil
}

// NewDeleteOptions instantiates the `delete` command options
func NewDeleteOptions(streams genericclioptions.IOStreams) CommandOptions {
	return &DeleteOptions{
		IOStreams: streams,
	}
}

// Delete creates the `delete` command
func Delete(streams genericclioptions.IOStreams, f factory.Factory) *cobra.Command {
	// o := NewDeleteOptions(streams).(*DeleteOptions)

	cmd := &cobra.Command{
		Use:                   "delete",
		DisableFlagsInUseLine: true,
		Short:                 "Delete a component wih falcoctl",
		Long:                  `Delete a component wih falcoctl`,
	}

	cmd.AddCommand(DeleteFalco(streams, f))

	return cmd
}
