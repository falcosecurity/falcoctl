// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2023 The Falco Authors
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
	"errors"
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
	*options.Common
	*options.Registry
}

// NewArtifactInfoCmd returns the artifact info command.
func NewArtifactInfoCmd(ctx context.Context, opt *options.Common) *cobra.Command {
	o := artifactInfoOptions{
		Common:   opt,
		Registry: &options.Registry{},
	}

	cmd := &cobra.Command{
		Use:                   "info [ref1 [ref2 ...]] [flags]",
		DisableFlagsInUseLine: true,
		Short:                 "Retrieve all available versions of a given artifact",
		Long:                  "Retrieve all available versions of a given artifact",
		Args:                  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return o.RunArtifactInfo(ctx, args)
		},
	}

	o.Registry.AddFlags(cmd)

	return cmd
}

func (o *artifactInfoOptions) RunArtifactInfo(ctx context.Context, args []string) error {
	var data [][]string
	logger := o.Printer.Logger

	client, err := ociutils.Client(true)
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
				logger.Warn("Cannot find artifact, skipping", logger.Args("name", name))
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
		if err != nil && !errors.Is(err, context.Canceled) {
			logger.Warn("Cannot retrieve tags from", logger.Args("ref", ref, "reason", err.Error()))
			continue
		} else if errors.Is(err, context.Canceled) {
			// When the context is canceled we exit, since we receive a termination signal.
			return err
		}

		joinedTags := strings.Join(filterOutSigTags(tags), ", ")
		data = append(data, []string{ref, joinedTags})
	}

	// Print the table header + data only if there is data.
	if len(data) > 0 {
		return o.Printer.PrintTable(output.ArtifactInfo, data)
	}

	return nil
}

func filterOutSigTags(tags []string) []string {
	// Iterate the slice in reverse to avoid index shifting when deleting
	for i := len(tags) - 1; i >= 0; i-- {
		if strings.HasSuffix(tags[i], ".sig") {
			// Remove the element at index i by slicing the slice
			tags = append(tags[:i], tags[i+1:]...)
		}
	}
	return tags
}
