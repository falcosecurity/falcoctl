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

	commonoptions "github.com/falcosecurity/falcoctl/pkg/options"
)

const (
	defaultFalcoctlPath    = ".falcoctl"
	defaultIndexesFilename = "indexes.yaml"
	timeFormat             = "2006-01-02 15:04:05"
)

func NewIndexCmd(ctx context.Context, opt *commonoptions.CommonOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:                   "index",
		DisableFlagsInUseLine: true,
		Short:                 "Interact with index",
		Long:                  "Interact with index",
	}

	cmd.AddCommand(NewIndexAddCmd(ctx, opt))
	cmd.AddCommand(NewIndexRemoveCmd(ctx, opt))
	cmd.AddCommand(NewIndexUpdateCmd(ctx, opt))
	cmd.AddCommand(NewIndexListCmd(ctx, opt))

	return cmd
}
