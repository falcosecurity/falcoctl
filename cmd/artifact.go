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

	"github.com/falcosecurity/falcoctl/internal/artifact/follow"
	"github.com/falcosecurity/falcoctl/internal/artifact/info"
	"github.com/falcosecurity/falcoctl/internal/artifact/install"
	"github.com/falcosecurity/falcoctl/internal/artifact/list"
	"github.com/falcosecurity/falcoctl/internal/artifact/search"
	commonoptions "github.com/falcosecurity/falcoctl/pkg/options"
)

// NewArtifactCmd return the artifact command.
func NewArtifactCmd(ctx context.Context, opt *commonoptions.CommonOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:                   "artifact",
		DisableFlagsInUseLine: true,
		Short:                 "Interact with Falco artifacts",
		Long:                  "Interact with Falco artifacts",
	}

	cmd.AddCommand(search.NewArtifactSearchCmd(ctx, opt))
	cmd.AddCommand(install.NewArtifactInstallCmd(ctx, opt))
	cmd.AddCommand(list.NewArtifactListCmd(ctx, opt))
	cmd.AddCommand(info.NewArtifactInfoCmd(ctx, opt))
	cmd.AddCommand(follow.NewArtifactFollowCmd(ctx, opt))

	return cmd
}
