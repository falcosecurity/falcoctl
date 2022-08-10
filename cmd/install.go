// Copyright 2022 The Falco Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"github.com/spf13/cobra"
)

// InstallOptions represents the install command options
type InstallOptions struct {
	*TLSOptions
}

// Validate validates the `install` command options
func (o *InstallOptions) Validate(c *cobra.Command, args []string) error {
	// todo > validate path exists and is writable here
	return nil
}

// NewInstallOptions instantiates the `install` command options
func NewInstallOptions() CommandOptions {
	return &InstallOptions{
		TLSOptions: NewTLSOptions(),
	}
}

// NewInstall creates the `install` command
func NewInstallCmd(options CommandOptions) *cobra.Command {
	o := options.(*InstallOptions)

	cmd := &cobra.Command{
		Use:                   "install",
		TraverseChildren:      true,
		DisableFlagsInUseLine: true,
		Short:                 "Install a component with falcoctl",
		Long:                  `Install a component with falcoctl`,
	}

	cmd.AddCommand(NewInstallFalcoCmd(nil))
	cmd.AddCommand(NewInstallTLSCmd(o.TLSOptions))
	cmd.AddCommand(NewInstallRuleCmd(nil))

	return cmd
}
