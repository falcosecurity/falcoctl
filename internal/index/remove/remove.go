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
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/falcosecurity/falcoctl/internal/config"
	"github.com/falcosecurity/falcoctl/pkg/index"
	"github.com/falcosecurity/falcoctl/pkg/options"
)

type indexRemoveOptions struct {
	*options.CommonOptions
	indexConfig *index.Config
}

func (o *indexRemoveOptions) Validate(args []string) error {
	// Check that all the index names are actually stored in the system.
	var err error
	o.indexConfig, err = index.NewConfig(config.IndexesFile)
	if err != nil {
		return err
	}

	for _, name := range args {
		if _, err := o.indexConfig.Get(name); err != nil {
			return fmt.Errorf("cannot remove %s: %w. Check that each passed index is cached in the system", name, err)
		}
	}

	return nil
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
		PreRun: func(cmd *cobra.Command, args []string) {
			o.Printer.CheckErr(o.Validate(args))
		},
		Run: func(cmd *cobra.Command, args []string) {
			o.Printer.CheckErr(o.RunIndexRemove(ctx, args))
		},
	}

	return cmd
}

func (o *indexRemoveOptions) RunIndexRemove(ctx context.Context, args []string) error {
	for _, name := range args {
		nameYaml := fmt.Sprintf("%s%s", name, ".yaml")
		indexFile := filepath.Join(config.FalcoctlPath, nameYaml)
		if err := o.indexConfig.Remove(name); err != nil {
			return err
		}

		if err := os.Remove(indexFile); err != nil {
			return err
		}
	}

	if err := o.indexConfig.Write(config.IndexesFile); err != nil {
		return err
	}

	return nil
}
