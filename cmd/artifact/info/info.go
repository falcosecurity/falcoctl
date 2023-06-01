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

package info

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"oras.land/oras-go/v2/registry"

	"github.com/falcosecurity/falcoctl/pkg/oci/repository"
	ociutils "github.com/falcosecurity/falcoctl/pkg/oci/utils"
	"github.com/falcosecurity/falcoctl/pkg/options"
	"github.com/falcosecurity/falcoctl/pkg/output"
)

type artifactInfoOptions struct {
	*options.CommonOptions
	*options.RegistryOptions
}

// NewArtifactInfoCmd returns the artifact info command.
func NewArtifactInfoCmd(ctx context.Context, opt *options.CommonOptions) *cobra.Command {
	o := artifactInfoOptions{
		CommonOptions:   opt,
		RegistryOptions: &options.RegistryOptions{},
	}

	cmd := &cobra.Command{
		Use:                   "info [ref1 [ref2 ...]] [flags]",
		DisableFlagsInUseLine: true,
		Short:                 "Retrieve all available versions of a given artifact",
		Long:                  "Retrieve all available versions of a given artifact",
		Args:                  cobra.MinimumNArgs(1),
		SilenceErrors:         true,
		SilenceUsage:          true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return o.RunArtifactInfo(ctx, args)
		},
	}

	o.RegistryOptions.AddFlags(cmd)

	return cmd
}

func (o *artifactInfoOptions) RunArtifactInfo(ctx context.Context, args []string) error {
	var data [][]string

	client, err := ociutils.Client()
	if err != nil {
		return err
	}

	// resolve references
	for _, name := range args {
		var ref string
		parsedRef, err := registry.ParseReference(name)
		if err != nil {
			entry, ok := o.IndexCache.MergedIndexes.EntryByName(name)
			if !ok {
				o.Printer.Warning.Printfln("cannot find %q, skipping", name)
				continue
			}
			ref = fmt.Sprintf("%s/%s", entry.Registry, entry.Repository)
		} else {
			parsedRef.Reference = ""
			ref = parsedRef.String()
		}

		repo, err := repository.NewRepository(ref,
			repository.WithClient(client),
			repository.WithPlainHTTP(o.PlainHTTP))
		if err != nil {
			return err
		}

		tags, err := repo.Tags(ctx)
		if err != nil {
			o.Printer.Warning.Printfln("cannot retrieve tags from %q, %v", ref, err)
			continue
		}

		joinedTags := strings.Join(tags, ", ")
		data = append(data, []string{ref, joinedTags})
	}

	return o.Printer.PrintTable(output.ArtifactInfo, data)
}
