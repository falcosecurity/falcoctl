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

package remove

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/falcosecurity/falcoctl/internal/config"
	"github.com/falcosecurity/falcoctl/pkg/index/cache"
	"github.com/falcosecurity/falcoctl/pkg/options"
)

type indexRemoveOptions struct {
	*options.CommonOptions
}

// NewIndexRemoveCmd returns the index remove command.
func NewIndexRemoveCmd(ctx context.Context, opt *options.CommonOptions) *cobra.Command {
	o := indexRemoveOptions{
		CommonOptions: opt,
	}

	cmd := &cobra.Command{
		Use:                   "remove [INDEX1 [INDEX2 ...]] [flags]",
		DisableFlagsInUseLine: true,
		Short:                 "Remove an index from the local falcoctl configuration",
		Long:                  "Remove an index from the local falcoctl configuration",
		Args:                  cobra.MinimumNArgs(1),
		Aliases:               []string{"rm"},
		SilenceErrors:         true,
		SilenceUsage:          true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return o.RunIndexRemove(ctx, args)
		},
	}

	return cmd
}

func (o *indexRemoveOptions) RunIndexRemove(ctx context.Context, args []string) error {
	o.Printer.Verbosef("Creating in-memory cache using indexes file %q and indexes directory %q", config.IndexesFile, config.IndexesDir)
	indexCache, err := cache.New(ctx, config.IndexesFile, config.IndexesDir)
	if err != nil {
		return fmt.Errorf("unable to create index cache: %w", err)
	}

	for _, name := range args {
		o.Printer.Info.Printfln("Removing index %q", name)
		if err = indexCache.Remove(name); err != nil {
			return fmt.Errorf("unable to remove index: %w", err)
		}
	}

	o.Printer.Verbosef("Writing cache to disk")
	if _, err = indexCache.Write(); err != nil {
		return fmt.Errorf("unable to write cache to disk: %w", err)
	}

	o.Printer.Verbosef("Removing indexes entries from configuration file %q", o.ConfigFile)
	if err = config.RemoveIndexes(args, o.ConfigFile); err != nil {
		return err
	}

	o.Printer.Success.Printfln("Indexes successfully removed")

	return nil
}
