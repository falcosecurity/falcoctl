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

	"github.com/spf13/cobra"

	"github.com/falcosecurity/falcoctl/pkg/index"
	"github.com/falcosecurity/falcoctl/pkg/options"
	"github.com/falcosecurity/falcoctl/pkg/output"
)

type artifactSearchOptions struct {
	*options.CommonOptions
}

// NewArtifactSearchCmd returns the artifact search command.
func NewArtifactSearchCmd(ctx context.Context, opt *options.CommonOptions) *cobra.Command {
	o := artifactSearchOptions{
		CommonOptions: opt,
	}

	cmd := &cobra.Command{
		Use:                   "search [keyword1 [keyword2 ...]] [flags]",
		DisableFlagsInUseLine: true,
		Short:                 "Search an artifact by keywords",
		Long:                  "Search an artifact by keywords",
		Args:                  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			o.Printer.CheckErr(o.RunArtifactSearch(ctx, args))
		},
	}

	return cmd
}

func (o *artifactSearchOptions) RunArtifactSearch(ctx context.Context, args []string) error {
	indexConfig, err := index.NewConfig(indexesFile)
	if err != nil {
		return err
	}

	var allIndexes []*index.Index

	// When reading from this file, entries are already ordered by added time.
	for _, indexConfigEntry := range indexConfig.Configs {
		nameYaml := fmt.Sprintf("%s%s", indexConfigEntry.Name, ".yaml")
		i, err := index.NewIndex(filepath.Join(falcoctlPath, nameYaml), indexConfigEntry.Name)
		if err != nil {
			return fmt.Errorf("cannot search: %w", err)
		}
		allIndexes = append(allIndexes, i)
	}

	mergedIndexes := index.NewMergedIndexes()
	mergedIndexes.Merge(allIndexes...)

	resultEntries := mergedIndexes.SearchByKeywords(args...)

	var data [][]string
	for _, entry := range resultEntries {
		indexName := mergedIndexes.IndexByEntry(entry).Name
		row := []string{indexName, entry.Name, entry.Type, entry.Registry, entry.Repository}
		data = append(data, row)
	}

	if err = o.Printer.PrintTable(output.ArtifactSearch, data); err != nil {
		return err
	}

	return nil
}
