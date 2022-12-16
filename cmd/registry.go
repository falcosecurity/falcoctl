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

	"github.com/falcosecurity/falcoctl/internal/registry/login"
	"github.com/falcosecurity/falcoctl/internal/registry/logout"
	"github.com/falcosecurity/falcoctl/internal/registry/oauth"
	"github.com/falcosecurity/falcoctl/internal/registry/pull"
	"github.com/falcosecurity/falcoctl/internal/registry/push"
	commonoptions "github.com/falcosecurity/falcoctl/pkg/options"
)

// NewRegistryCmd returns the registry command.
func NewRegistryCmd(ctx context.Context, opt *commonoptions.CommonOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:                   "registry",
		DisableFlagsInUseLine: true,
		Short:                 "Interact with OCI registries",
		Long:                  "Interact with OCI registries",
	}

	cmd.AddCommand(login.NewLoginCmd(ctx, opt))
	cmd.AddCommand(logout.NewLogoutCmd(opt))
	cmd.AddCommand(push.NewPushCmd(ctx, opt))
	cmd.AddCommand(pull.NewPullCmd(ctx, opt))
	cmd.AddCommand(oauth.NewOauthCmd(ctx, opt))

	return cmd
}
