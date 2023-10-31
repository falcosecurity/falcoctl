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

package artifact

import (
	"context"

	"github.com/spf13/cobra"

	artifactconfig "github.com/falcosecurity/falcoctl/cmd/artifact/config"
	"github.com/falcosecurity/falcoctl/cmd/artifact/follow"
	"github.com/falcosecurity/falcoctl/cmd/artifact/info"
	"github.com/falcosecurity/falcoctl/cmd/artifact/install"
	"github.com/falcosecurity/falcoctl/cmd/artifact/list"
	"github.com/falcosecurity/falcoctl/cmd/artifact/search"
	"github.com/falcosecurity/falcoctl/internal/config"
	"github.com/falcosecurity/falcoctl/pkg/index/cache"
	commonoptions "github.com/falcosecurity/falcoctl/pkg/options"
)

// NewArtifactCmd return the artifact command.
func NewArtifactCmd(ctx context.Context, opt *commonoptions.Common) *cobra.Command {
	cmd := &cobra.Command{
		Use:                   "artifact",
		DisableFlagsInUseLine: true,
		Short:                 "Interact with Falco artifacts",
		Long:                  "Interact with Falco artifacts",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			var indexes []config.Index
			var indexCache *cache.Cache
			var err error

			opt.Initialize()
			if err = config.Load(opt.ConfigFile); err != nil {
				return err
			}

			// add indexes if needed
			// Set up basic authentication
			if indexes, err = config.Indexes(); err != nil {
				return err
			}

			// Create the index cache.
			if indexCache, err = cache.NewFromConfig(ctx, config.IndexesFile, config.IndexesDir, indexes); err != nil {
				return err
			}
			// Save the index cache for later use by the sub commands.
			opt.Initialize(commonoptions.WithIndexCache(indexCache))

			return nil
		},
	}

	cmd.AddCommand(search.NewArtifactSearchCmd(ctx, opt))
	cmd.AddCommand(install.NewArtifactInstallCmd(ctx, opt))
	cmd.AddCommand(list.NewArtifactListCmd(ctx, opt))
	cmd.AddCommand(info.NewArtifactInfoCmd(ctx, opt))
	cmd.AddCommand(follow.NewArtifactFollowCmd(ctx, opt))
	cmd.AddCommand(artifactconfig.NewArtifactConfigCmd(ctx, opt))

	return cmd
}
