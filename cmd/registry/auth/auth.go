// Copyright 2023 The Falco Authors
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

package auth

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/falcosecurity/falcoctl/cmd/registry/auth/basic"
	"github.com/falcosecurity/falcoctl/cmd/registry/auth/gcp"
	"github.com/falcosecurity/falcoctl/cmd/registry/auth/oauth"
	commonoptions "github.com/falcosecurity/falcoctl/pkg/options"
)

// NewAuthCmd returns the registry command.
func NewAuthCmd(ctx context.Context, opt *commonoptions.Common) *cobra.Command {
	cmd := &cobra.Command{
		Use:                   "auth",
		DisableFlagsInUseLine: true,
		Short:                 "Handle authentication towards OCI registries",
		Long:                  "Handle authentication towards OCI registries",
		SilenceErrors:         true,
	}

	cmd.AddCommand(basic.NewBasicCmd(ctx, opt))
	cmd.AddCommand(oauth.NewOauthCmd(ctx, opt))
	cmd.AddCommand(gcp.NewGcpCmd(ctx, opt))

	return cmd
}
