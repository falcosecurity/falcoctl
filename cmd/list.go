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

import "github.com/spf13/cobra"

// Defaults.
const ()

// ListOptions represents the install command options
type ListOptions struct {
	*ListRepoOptions
	RepoPath string
	RepoFile string
}

// Validate validates the `list` command options
func (o *ListOptions) Validate(c *cobra.Command, args []string) error {
	//TODO
	return nil
}

func (o *ListOptions) AddFlags(c *cobra.Command) {
}

// NewRepoOptions instantiates the `repo` command options
func NewListOptions() CommandOptions {
	return &ListOptions{
		ListRepoOptions: NewListRepoOptions(),
		RepoPath:        defaultRepoPath,
		RepoFile:        defaultRepoFile,
	}
}

func NewListCmd(options CommandOptions) *cobra.Command {
	o := options.(*ListOptions)
	cmd := &cobra.Command{
		Use:                   "list",
		DisableFlagsInUseLine: true,
		Short:                 "Print list of resources",
		Long:                  "Print list of resources",
	}

	cmd.AddCommand(NewListRepoCmd(o))

	return cmd
}
