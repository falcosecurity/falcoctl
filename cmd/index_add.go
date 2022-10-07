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
	"time"

	"github.com/spf13/cobra"

	"github.com/falcosecurity/falcoctl/pkg/index"
	"github.com/falcosecurity/falcoctl/pkg/options"
)

type indexAddOptions struct {
	*options.CommonOptions
}

func (o *indexAddOptions) Validate(args []string) error {
	// TODO(loresuso): we should move this logic elsewhere
	if _, err := os.Stat(falcoctlPath); os.IsNotExist(err) {
		err = os.Mkdir(falcoctlPath, 0o700)
		if err != nil {
			return err
		}
	}
	return nil
}

// NewIndexAddCmd returns the index add command.
func NewIndexAddCmd(ctx context.Context, opt *options.CommonOptions) *cobra.Command {
	o := indexAddOptions{
		CommonOptions: opt,
	}

	cmd := &cobra.Command{
		Use:                   "add [NAME] [URL] [flags]",
		DisableFlagsInUseLine: true,
		Short:                 "Add an index to the local falcoctl configuration",
		Long:                  "Add an index to the local falcoctl configuration. Indexes are used to perform search operations for artifacts",
		Args:                  cobra.ExactArgs(2),
		PreRun: func(cmd *cobra.Command, args []string) {
			o.Printer.CheckErr(o.Validate(args))
		},
		Run: func(cmd *cobra.Command, args []string) {
			o.Printer.CheckErr(o.RunIndexAdd(ctx, args))
		},
	}

	return cmd
}

func (o *indexAddOptions) RunIndexAdd(ctx context.Context, args []string) error {
	name := args[0]
	nameYaml := fmt.Sprintf("%s%s", name, ".yaml")
	url := args[1]

	indexFile := filepath.Join(falcoctlPath, nameYaml)

	indexConfig, err := index.NewConfig(indexesFile)
	if err != nil {
		return err
	}

	if _, err := indexConfig.Get(name); err == nil {
		o.Printer.Warning.Printf("%s already exists with the same configuration, skipping\n", name)
		return nil
	}

	remoteIndex, err := index.Fetch(ctx, url, name)
	if err != nil {
		return err
	}

	// Save the new index.
	err = remoteIndex.Write(indexFile)
	if err != nil {
		return err
	}

	// Keep track of the newly created index file in indexes.yaml.
	ts := time.Now().Format(timeFormat)
	entry := index.ConfigEntry{
		Name:             name,
		AddedTimestamp:   ts,
		UpdatedTimestamp: ts,
		URL:              url,
	}

	indexConfig.Add(entry)

	if err := indexConfig.Write(indexesFile); err != nil {
		return err
	}

	return nil
}
