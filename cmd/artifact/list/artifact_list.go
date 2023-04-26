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

package list

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/falcosecurity/falcoctl/pkg/oci"
	"github.com/falcosecurity/falcoctl/pkg/options"
	"github.com/falcosecurity/falcoctl/pkg/output"
)

type artifactListOptions struct {
	*options.CommonOptions
	artifactType oci.ArtifactType
	index        string
}

// NewArtifactListCmd returns the artifact search command.
func NewArtifactListCmd(ctx context.Context, opt *options.CommonOptions) *cobra.Command {
	o := artifactListOptions{
		CommonOptions: opt,
	}

	cmd := &cobra.Command{
		Use:                   "list [flags]",
		DisableFlagsInUseLine: true,
		Short:                 "List all artifacts",
		Long:                  "List all artifacts",
		Aliases:               []string{"ls"},
		SilenceErrors:         true,
		SilenceUsage:          true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return o.RunArtifactList(ctx, args)
		},
	}

	cmd.Flags().Var(&o.artifactType, "type", `Only list artifacts with a specific type. Allowed values: "rulesfile", "plugin""`)
	cmd.Flags().StringVar(&o.index, "index", "", "Only display artifacts from a configured index")

	return cmd
}

func (o *artifactListOptions) RunArtifactList(_ context.Context, _ []string) error {
	var data [][]string
	for _, entry := range o.IndexCache.MergedIndexes.Entries {
		if o.artifactType != "" && o.artifactType != oci.ArtifactType(entry.Type) {
			continue
		}

		indexName := o.IndexCache.MergedIndexes.IndexByEntry(entry).Name
		if o.index != "" && o.index != indexName {
			continue
		}

		row := []string{indexName, entry.Name, entry.Type, entry.Registry, entry.Repository}
		data = append(data, row)
	}

	return o.Printer.PrintTable(output.ArtifactSearch, data)
}
