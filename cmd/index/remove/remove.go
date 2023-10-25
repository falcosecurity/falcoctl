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
	*options.Common
}

// NewIndexRemoveCmd returns the index remove command.
func NewIndexRemoveCmd(ctx context.Context, opt *options.Common) *cobra.Command {
	o := indexRemoveOptions{
		Common: opt,
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
	logger := o.Printer.Logger

	logger.Debug("Creating in-memory cache using", logger.Args("indexes file", config.IndexesFile, "indexes directory", config.IndexesDir))
	indexCache, err := cache.New(ctx, config.IndexesFile, config.IndexesDir)
	if err != nil {
		return fmt.Errorf("unable to create index cache: %w", err)
	}

	for _, name := range args {
		logger.Info("Removing index", logger.Args("name", name))
		if err = indexCache.Remove(name); err != nil {
			return fmt.Errorf("unable to remove index: %w", err)
		}
	}

	logger.Debug("Writing cache to disk")
	if _, err = indexCache.Write(); err != nil {
		return fmt.Errorf("unable to write cache to disk: %w", err)
	}

	logger.Debug("Removing indexes entries from configuration", logger.Args("file", o.ConfigFile))
	if err = config.RemoveIndexes(args, o.ConfigFile); err != nil {
		return err
	}

	logger.Info("Indexes successfully removed")

	return nil
}
