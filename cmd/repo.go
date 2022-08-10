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
const (
	DefaultRepoPath = ".falcoctl"
	DefaultRepoFile = "sources.yaml"
)

// RepoOptions represents the install command options
type RepoOptions struct {
	*RepoAddOptions
	*RepoRemoveOptions
	RepoPath string
	RepoFile string
}

// Validate validates the `install` command options
func (o *RepoOptions) Validate(c *cobra.Command, args []string) error {
	//TODO
	return nil
}

func (o *RepoOptions) AddFlags(c *cobra.Command) {

}

// NewRepoOptions instantiates the `repo` command options
func NewRepoOptions() CommandOptions {
	return &RepoOptions{
		RepoAddOptions:    NewRepoAddOptions(),
		RepoRemoveOptions: NewRepoRemoveOptions(),
		RepoPath:          DefaultRepoPath,
		RepoFile:          DefaultRepoFile,
	}
}

func NewRepoCmd(options CommandOptions) *cobra.Command {
	o := options.(*RepoOptions)
	cmd := &cobra.Command{
		Use:                   "repo",
		DisableFlagsInUseLine: true,
		Short:                 "Manage artifact repositories",
		Long:                  "Manage artifact repositories",
	}

	cmd.AddCommand(NewRepoAddCmd(o))
	cmd.AddCommand(NewRepoRemoveCmd(o))

	return cmd
}
