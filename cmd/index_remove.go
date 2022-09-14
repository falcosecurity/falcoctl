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
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/docker/docker/pkg/homedir"
	"github.com/spf13/cobra"

	"github.com/falcosecurity/falcoctl/pkg/index"
	"github.com/falcosecurity/falcoctl/pkg/options"
)

type indexRemoveOptions struct {
	*options.CommonOptions
}

func (o *indexRemoveOptions) Validate(args []string) error {
	// TODO
	return nil
}

func NewIndexRemoveCmd(ctx context.Context, opt *options.CommonOptions) *cobra.Command {
	o := indexAddOptions{
		CommonOptions: opt,
	}

	cmd := &cobra.Command{
		Use:                   "remove [name]",
		DisableFlagsInUseLine: true,
		Short:                 "Remove an index from the list of indexes",
		Long:                  "Remove an index from the list of indexes. Indexes are used to perform search for artifacts.",
		Args:                  cobra.ExactArgs(1),
		Aliases:               []string{"rm"},
		PreRun: func(cmd *cobra.Command, args []string) {
			o.Printer.CheckErr(o.Validate(args))
		},
		Run: func(cmd *cobra.Command, args []string) {
			o.Printer.CheckErr(o.RunIndexRemove(ctx, args))
		},
	}

	return cmd
}

func (o *indexAddOptions) RunIndexRemove(ctx context.Context, args []string) error {
	name := args[0]
	nameYaml := fmt.Sprintf("%s%s", name, ".yaml")
	falcoctlPath := filepath.Join(homedir.Get(), defaultFalcoctlPath)
	indexesFile := filepath.Join(falcoctlPath, defaultIndexesFilename)
	indexFile := filepath.Join(falcoctlPath, nameYaml)

	indexConfig, err := index.NewIndexConfig(indexesFile)
	if err != nil {
		return err
	}

	if err := indexConfig.Remove(name); err != nil {
		return err
	}

	if err := indexConfig.Write(indexesFile); err != nil {
		return err
	}

	if err := os.Remove(indexFile); err != nil {
		return err
	}

	return nil
}
