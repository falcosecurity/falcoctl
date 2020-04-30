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
)

// ConvertOptions represents the convert command options
type ConvertOptions struct {
	*PspConvertOptions
}

func (o *ConvertOptions) AddFlags(c *cobra.Command) {

}

// Validate validates the `convert` command options
func (o *ConvertOptions) Validate(c *cobra.Command, args []string) error {
	return nil
}

// NewConvertOptions instantiates the `convert` command options
func NewConvertOptions() CommandOptions {
	return &ConvertOptions{
		PspConvertOptions: NewPspConvertOptions(),
	}
}

// NewConvert creates the `convert` command
func NewConvertCmd(options CommandOptions) *cobra.Command {
	o := options.(*ConvertOptions)

	cmd := &cobra.Command{
		Use:                   "convert",
		TraverseChildren:      true,
		DisableFlagsInUseLine: true,
		Short:                 "Conversion helpers",
		Long:                  `Various conversion helpers`,
	}

	o.AddFlags(cmd)

	cmd.AddCommand(NewPspConvertCmd(o.PspConvertOptions))

	return cmd
}
