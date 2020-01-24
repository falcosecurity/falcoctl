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
	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
)

// ConvertOptions represents the convert command options
type ConvertOptions struct {
	genericclioptions.IOStreams
}

// Validate validates the `convert` command options
func (o ConvertOptions) Validate(c *cobra.Command, args []string) error {
	return nil
}

// NewConvertOptions instantiates the `convert` command options
func NewConvertOptions(streams genericclioptions.IOStreams) CommandOptions {
	return &ConvertOptions{
		IOStreams: streams,
	}
}

// Convert creates the `convert` command
func Convert(streams genericclioptions.IOStreams) *cobra.Command {
	// o := NewConvertOptions(streams).(*ConvertOptions)

	cmd := &cobra.Command{
		Use:                   "convert",
		TraverseChildren:      true,
		DisableFlagsInUseLine: true,
		Short:                 "Conversion helpers",
		Long:                  `Various conversion helpers`,
	}

	cmd.AddCommand(PspConvert(streams))

	return cmd
}
