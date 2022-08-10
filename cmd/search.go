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

// InstallOptions represents the install command options
type SearchOptions struct {
	*SearchRegOptions
}

// Validate validates the `install` command options
func (o *SearchOptions) Validate(c *cobra.Command, args []string) error {
	// todo > validate path exists and is writable here
	return nil
}

// NewSearchOptions instantiates the `search` command options
func NewSearchOptions() CommandOptions {
	return &SearchOptions{
		SearchRegOptions: NewSearchRegOptions(),
	}
}

func NewSearchCmd(options CommandOptions) *cobra.Command {
	o := options.(*SearchOptions)
	cmd := &cobra.Command{
		Use:                   "search",
		DisableFlagsInUseLine: true,
		Short:                 "Search a component with falcoctl",
		Long:                  "Search a component with falcoctl",
	}

	cmd.AddCommand(NewSearchRegistryCmd(o.SearchRegOptions))

	return cmd
}
