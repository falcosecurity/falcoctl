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

	"github.com/spf13/cobra"

	"github.com/falcosecurity/falcoctl/pkg/index"
	"github.com/falcosecurity/falcoctl/pkg/options"
	"github.com/falcosecurity/falcoctl/pkg/output"
)

type indexListOptions struct {
	*options.CommonOptions
}

// NewIndexListCmd returns the index list command.
func NewIndexListCmd(ctx context.Context, opt *options.CommonOptions) *cobra.Command {
	o := indexListOptions{
		CommonOptions: opt,
	}

	cmd := &cobra.Command{
		Use:                   "list [flags]",
		DisableFlagsInUseLine: true,
		Short:                 "List all the added indexes",
		Long:                  "List all the added indexes that were cached in this system",
		Args:                  cobra.ExactArgs(0),
		Aliases:               []string{"ls"},
		Run: func(cmd *cobra.Command, args []string) {
			o.Printer.CheckErr(o.RunIndexList(ctx, args))
		},
	}

	return cmd
}

func (o *indexListOptions) RunIndexList(ctx context.Context, args []string) error {
	indexConfig, err := index.NewConfig(indexesFile)
	if err != nil {
		return err
	}

	var data [][]string
	for _, conf := range indexConfig.Configs {
		newEntry := []string{conf.Name, conf.URL, conf.AddedTimestamp, conf.UpdatedTimestamp}
		data = append(data, newEntry)
	}

	if err = o.Printer.PrintTable(output.IndexList, data); err != nil {
		return err
	}

	return nil
}
