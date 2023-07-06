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

package add

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/falcosecurity/falcoctl/internal/config"
	"github.com/falcosecurity/falcoctl/pkg/index/cache"
	"github.com/falcosecurity/falcoctl/pkg/options"
)

// IndexAddOptions contains the options for the index add command.
type IndexAddOptions struct {
	*options.CommonOptions
}

// NewIndexAddCmd returns the index add command.
func NewIndexAddCmd(ctx context.Context, opt *options.CommonOptions) *cobra.Command {
	o := IndexAddOptions{
		CommonOptions: opt,
	}

	cmd := &cobra.Command{
		Use:                   "add [NAME] [URL] [BACKEND] [flags]",
		DisableFlagsInUseLine: true,
		Short:                 "Add an index to the local falcoctl configuration",
		Long:                  "Add an index to the local falcoctl configuration. Indexes are used to perform search operations for artifacts",
		Args:                  cobra.RangeArgs(2, 3),
		SilenceErrors:         true,
		SilenceUsage:          true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return o.RunIndexAdd(ctx, args)
		},
	}

	return cmd
}

// RunIndexAdd implements the index add command.
func (o *IndexAddOptions) RunIndexAdd(ctx context.Context, args []string) error {
	var err error

	name := args[0]
	url := args[1]
	backend := ""
	if len(args) > 2 {
		backend = args[2]
	}

	o.Printer.Verbosef("Creating in-memory cache using indexes file %q and indexes directory %q", config.IndexesFile, config.IndexesDir)
	indexCache, err := cache.New(ctx, config.IndexesFile, config.IndexesDir)
	if err != nil {
		return fmt.Errorf("unable to create index cache: %w", err)
	}

	o.Printer.Info.Printfln("Adding index")

	if err = indexCache.Add(ctx, name, backend, url); err != nil {
		return fmt.Errorf("unable to add index: %w", err)
	}

	o.Printer.Verbosef("Writing cache to disk")
	if _, err = indexCache.Write(); err != nil {
		return fmt.Errorf("unable to write cache to disk: %w", err)
	}

	o.Printer.Verbosef("Adding new index entry to configuration file %q", o.ConfigFile)
	if err = config.AddIndexes([]config.Index{{
		Name:    name,
		URL:     url,
		Backend: backend,
	}}, o.ConfigFile); err != nil {
		return fmt.Errorf("index entry %q: %w", name, err)
	}

	o.Printer.Success.Printfln("Index %q successfully added", name)

	return nil
}
