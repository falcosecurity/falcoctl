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

	"github.com/spf13/cobra"

	"github.com/falcosecurity/falcoctl/cmd/internal/utils"
	"github.com/falcosecurity/falcoctl/pkg/index"
	"github.com/falcosecurity/falcoctl/pkg/options"
	"github.com/falcosecurity/falcoctl/pkg/output"
)

const (
	defaultMinScore = 0.65
)

type artifactSearchOptions struct {
	*options.CommonOptions
	minScore float64
}

func (o *artifactSearchOptions) Validate() error {
	if o.minScore <= 0 || o.minScore > 1 {
		return fmt.Errorf("minScore must be a number within (0,1]")
	}

	return nil
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
		PreRun: func(cmd *cobra.Command, args []string) {
			o.Printer.CheckErr(o.Validate())
		},
		Run: func(cmd *cobra.Command, args []string) {
			o.Printer.CheckErr(o.RunArtifactSearch(ctx, args))
		},
	}

	cmd.Flags().Float64VarP(&o.minScore, "min-score", "", defaultMinScore,
		"the minimum score used to match artifact names with search keywords")

	return cmd
}

func (o *artifactSearchOptions) RunArtifactSearch(ctx context.Context, args []string) error {
	indexConfig, err := index.NewConfig(indexesFile)
	if err != nil {
		return err
	}

	mergedIndexes, err := utils.Indexes(indexConfig, falcoctlPath)
	if err != nil {
		return err
	}

	resultEntries := mergedIndexes.SearchByKeywords(o.minScore, args...)

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
