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
	"path/filepath"
	"time"

	"github.com/docker/docker/pkg/homedir"
	"github.com/spf13/cobra"

	"github.com/falcosecurity/falcoctl/pkg/index"
	"github.com/falcosecurity/falcoctl/pkg/options"
)

type indexAddOptions struct {
	*options.CommonOptions
}

func (o *indexAddOptions) Validate(args []string) error {
	// TODO
	return nil
}

func NewIndexAddCmd(ctx context.Context, opt *options.CommonOptions) *cobra.Command {
	o := indexAddOptions{
		CommonOptions: opt,
	}

	cmd := &cobra.Command{
		Use:                   "add [name] [URL]",
		DisableFlagsInUseLine: true,
		Short:                 "Add an index to the list of indexes",
		Long:                  "Add an index to the list of indexes. Indexes are used to perform search for artifacts.",
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
	falcoctlPath := filepath.Join(homedir.Get(), defaultFalcoctlPath)
	indexesFile := filepath.Join(falcoctlPath, defaultIndexesFilename)
	indexFile := filepath.Join(falcoctlPath, nameYaml)

	indexConfig, err := index.NewIndexConfig(indexesFile)
	if err != nil {
		return err
	}

	if _, err := indexConfig.Get(name); err == nil {
		return fmt.Errorf("cannot add already existing index: %s", name)
	}

	remoteIndex, err := index.FetchIndex(url)
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
	entry := index.IndexConfigEntry{
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
