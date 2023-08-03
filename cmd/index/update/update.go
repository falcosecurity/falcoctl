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

package update

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/falcosecurity/falcoctl/internal/config"
	"github.com/falcosecurity/falcoctl/pkg/index/cache"
	"github.com/falcosecurity/falcoctl/pkg/options"
)

type indexUpdateOptions struct {
	*options.Common
}

// NewIndexUpdateCmd returns the index update command.
func NewIndexUpdateCmd(ctx context.Context, opt *options.Common) *cobra.Command {
	o := indexUpdateOptions{
		Common: opt,
	}

	cmd := &cobra.Command{
		Use:                   "update [INDEX1 [INDEX2 ...]] [flags]",
		DisableFlagsInUseLine: true,
		Short:                 "Update an existing index",
		Long:                  "Update an existing index",
		Args:                  cobra.MinimumNArgs(1),
		SilenceErrors:         true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return o.RunIndexUpdate(ctx, args)
		},
	}

	return cmd
}

func (o *indexUpdateOptions) RunIndexUpdate(ctx context.Context, args []string) error {
	o.Printer.Verbosef("Creating in-memory cache using indexes file %q and indexes directory %q", config.IndexesFile, config.IndexesDir)
	indexCache, err := cache.New(ctx, config.IndexesFile, config.IndexesDir)
	if err != nil {
		return fmt.Errorf("unable to create index cache: %w", err)
	}

	for _, arg := range args {
		o.Printer.Info.Printfln("Updating index %q", arg)
		if err := indexCache.Update(ctx, arg); err != nil {
			return fmt.Errorf("an error occurred while updating index %q: %w", arg, err)
		}
	}

	o.Printer.Verbosef("Writing cache to disk")
	if _, err = indexCache.Write(); err != nil {
		return fmt.Errorf("unable to write cache to disk: %w", err)
	}

	o.Printer.Success.Printfln("Indexes successfully updated")

	return nil
}
