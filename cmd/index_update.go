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

	"github.com/docker/docker/pkg/homedir"
	"github.com/falcosecurity/falcoctl/pkg/index"
	"github.com/falcosecurity/falcoctl/pkg/options"
	"github.com/spf13/cobra"
)

type indexUpdateOptions struct {
	*options.CommonOptions
}

func (o *indexUpdateOptions) Validate(args []string) error {
	// TODO
	return nil
}

func NewIndexUpdateCmd(ctx context.Context, opt *options.CommonOptions) *cobra.Command {
	o := indexAddOptions{
		CommonOptions: opt,
	}

	cmd := &cobra.Command{
		Use:                   "update [name]",
		DisableFlagsInUseLine: true,
		Short:                 "Update an existing index",
		Long:                  "Update an existing index.",
		Args:                  cobra.ExactArgs(1),
		PreRun: func(cmd *cobra.Command, args []string) {
			o.Printer.CheckErr(o.Validate(args))
		},
		Run: func(cmd *cobra.Command, args []string) {
			o.Printer.CheckErr(o.RunIndexUpdate(ctx, args))
		},
	}

	return cmd
}

func (o *indexAddOptions) RunIndexUpdate(ctx context.Context, args []string) error {
	name := args[0]
	nameYaml := fmt.Sprintf("%s%s", name, ".yaml")
	falcoctlPath := filepath.Join(homedir.Get(), defaultFalcoctlPath)
	indexesFile := filepath.Join(falcoctlPath, defaultIndexesFilename)
	indexFile := filepath.Join(falcoctlPath, nameYaml)

	indexConfig, err := index.NewIndexConfig(indexesFile)
	if err != nil {
		return err
	}

	indexConfigEntry, err := indexConfig.Get(name)
	if err != nil {
		return fmt.Errorf("cannot update index %s: not found", name)
	}

	remoteIndex, err := index.GetIndex(indexConfigEntry.URL)
	if err != nil {
		return err
	}

	err = remoteIndex.Write(indexFile)
	if err != nil {
		return err
	}

	ts := time.Now().Format(timeFormat)
	indexConfigEntry.UpdatedTimestamp = ts

	indexConfig.Write(indexesFile)

	return nil
}
