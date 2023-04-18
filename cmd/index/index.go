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

package index

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/falcosecurity/falcoctl/cmd/index/add"
	"github.com/falcosecurity/falcoctl/cmd/index/list"
	"github.com/falcosecurity/falcoctl/cmd/index/remove"
	"github.com/falcosecurity/falcoctl/cmd/index/update"
	"github.com/falcosecurity/falcoctl/internal/config"
	commonoptions "github.com/falcosecurity/falcoctl/pkg/options"
)

// NewIndexCmd returns the index command.
func NewIndexCmd(ctx context.Context, opt *commonoptions.CommonOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:                   "index",
		DisableFlagsInUseLine: true,
		Short:                 "Interact with index",
		Long:                  "Interact with index",
		SilenceErrors:         true,
		SilenceUsage:          true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			opt.Initialize()
			return config.Load(opt.ConfigFile)
		},
	}

	cmd.AddCommand(add.NewIndexAddCmd(ctx, opt))
	cmd.AddCommand(remove.NewIndexRemoveCmd(ctx, opt))
	cmd.AddCommand(update.NewIndexUpdateCmd(ctx, opt))
	cmd.AddCommand(list.NewIndexListCmd(ctx, opt))

	return cmd
}
