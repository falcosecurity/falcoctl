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
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/falcosecurity/falcoctl/internal/config"
	"github.com/falcosecurity/falcoctl/internal/consts"
	"github.com/falcosecurity/falcoctl/pkg/index"
	"github.com/falcosecurity/falcoctl/pkg/options"
)

// IndexAddOptions contains the options for the index add command.
type IndexAddOptions struct {
	*options.CommonOptions
}

// Validate is used to make sure that required directories are existing in the filesystem.
func (o *IndexAddOptions) Validate(args []string) error {
	// TODO(loresuso): we should move this logic elsewhere
	if _, err := os.Stat(config.FalcoctlPath); os.IsNotExist(err) {
		err = os.MkdirAll(config.FalcoctlPath, 0o700)
		if err != nil {
			return err
		}
	}

	if _, err := os.Stat(config.IndexesDir); os.IsNotExist(err) {
		err = os.MkdirAll(config.IndexesDir, 0o700)
		if err != nil {
			return err
		}
	}
	return nil
}

// NewIndexAddCmd returns the index add command.
func NewIndexAddCmd(ctx context.Context, opt *options.CommonOptions) *cobra.Command {
	o := IndexAddOptions{
		CommonOptions: opt,
	}

	cmd := &cobra.Command{
		Use:                   "add [NAME] [URL] [flags]",
		DisableFlagsInUseLine: true,
		Short:                 "Add an index to the local falcoctl configuration",
		Long:                  "Add an index to the local falcoctl configuration. Indexes are used to perform search operations for artifacts",
		Args:                  cobra.ExactArgs(2),
		PreRun: func(cmd *cobra.Command, args []string) {
			o.Printer.CheckErr(o.Validate(args))
		},
		Run: func(cmd *cobra.Command, args []string) {
			o.Printer.CheckErr(o.RunIndexAdd(ctx, args))
		},
	}

	return cmd
}

// RunIndexAdd implements the index add command.
func (o *IndexAddOptions) RunIndexAdd(ctx context.Context, args []string) error {
	name := args[0]
	nameYaml := fmt.Sprintf("%s%s", name, ".yaml")
	url := args[1]
	indexFile := filepath.Join(config.IndexesDir, nameYaml)

	indexConfig, err := index.NewConfig(config.IndexesFile)
	if err != nil {
		return err
	}

	if e := indexConfig.Get(name); e != nil {
		o.Printer.Warning.Printf("%s already exists with the same configuration, skipping\n", name)
		return nil
	}

	remoteIndex, err := index.Fetch(ctx, url, name)
	if err != nil {
		return err
	}

	// Save the new index.
	err = remoteIndex.Write(indexFile)
	if err != nil {
		return err
	}

	// Keep track of the newly created index file in indexes.yaml.
	ts := time.Now().Format(consts.TimeFormat)
	entry := index.ConfigEntry{
		Name:             name,
		AddedTimestamp:   ts,
		UpdatedTimestamp: ts,
		URL:              url,
	}

	indexConfig.Add(entry)

	if err := indexConfig.Write(config.IndexesFile); err != nil {
		return err
	}

	currentIndexes, err := config.Indexes()
	if err != nil {
		return fmt.Errorf("unable to get indexes from viper: %w", err)
	}

	for _, i := range currentIndexes {
		if i.Name == name {
			o.Printer.Verbosef("index with name %q already exists in the config file %q", name, config.ConfigPath)
			return nil
		}
	}

	currentIndexes = append(currentIndexes, config.Index{
		Name: name,
		URL:  url,
	})

	if err := config.UpdateConfigFile(config.IndexesKey, currentIndexes, o.ConfigFile); err != nil {
		return fmt.Errorf("unable to update indexes list in the config file %q: %w", config.ConfigPath, err)
	}

	return nil
}
