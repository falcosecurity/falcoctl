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

	"github.com/spf13/cobra"

	"github.com/falcosecurity/falcoctl/pkg/index"
	"github.com/falcosecurity/falcoctl/pkg/options"
)

type indexUpdateOptions struct {
	*options.CommonOptions
}

func (o *indexUpdateOptions) Validate(args []string) error {
	// Check that all the index names are actually stored in the system.
	indexConfig, err := index.NewConfig(indexesFile)
	if err != nil {
		return err
	}

	for _, name := range args {
		if _, err := indexConfig.Get(name); err != nil {
			return fmt.Errorf("Cannot update %s: %w. Check that each passed index is cached in the system", name, err)
		}
	}

	return nil
}

// NewIndexUpdateCmd returns the index update command.
func NewIndexUpdateCmd(ctx context.Context, opt *options.CommonOptions) *cobra.Command {
	o := indexUpdateOptions{
		CommonOptions: opt,
	}

	cmd := &cobra.Command{
		Use:                   "update [INDEX1 [INDEX2 ...]] [flags]",
		DisableFlagsInUseLine: true,
		Short:                 "Update an existing index",
		Long:                  "Update an existing index",
		Args:                  cobra.MinimumNArgs(1),
		PreRun: func(cmd *cobra.Command, args []string) {
			o.Printer.CheckErr(o.Validate(args))
		},
		Run: func(cmd *cobra.Command, args []string) {
			o.Printer.CheckErr(o.RunIndexUpdate(ctx, args))
		},
	}

	return cmd
}

func (o *indexUpdateOptions) RunIndexUpdate(ctx context.Context, args []string) error {
	indexConfig, err := index.NewConfig(indexesFile)
	if err != nil {
		return err
	}

	ts := time.Now().Format(timeFormat)

	for _, name := range args {
		nameYaml := fmt.Sprintf("%s%s", name, ".yaml")
		indexFile := filepath.Join(falcoctlPath, nameYaml)

		indexConfigEntry, err := indexConfig.Get(name)
		if err != nil {
			return fmt.Errorf("cannot update index %s: not found", name)
		}

		remoteIndex, err := index.FetchIndex(ctx, indexConfigEntry.URL)
		if err != nil {
			return err
		}

		err = remoteIndex.Write(indexFile)
		if err != nil {
			return err
		}

		indexConfigEntry.UpdatedTimestamp = ts
	}

	if err = indexConfig.Write(indexesFile); err != nil {
		return err
	}

	return nil
}
