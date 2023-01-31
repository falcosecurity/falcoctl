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

package artifact

import (
	"context"

	"github.com/spf13/cobra"
	"golang.org/x/oauth2/clientcredentials"
	"oras.land/oras-go/v2/registry/remote/auth"

	"github.com/falcosecurity/falcoctl/cmd/artifact/follow"
	"github.com/falcosecurity/falcoctl/cmd/artifact/info"
	"github.com/falcosecurity/falcoctl/cmd/artifact/install"
	"github.com/falcosecurity/falcoctl/cmd/artifact/list"
	"github.com/falcosecurity/falcoctl/cmd/artifact/search"
	"github.com/falcosecurity/falcoctl/cmd/registry/auth/basic"
	"github.com/falcosecurity/falcoctl/cmd/registry/auth/oauth"
	"github.com/falcosecurity/falcoctl/internal/config"
	"github.com/falcosecurity/falcoctl/pkg/index/cache"
	commonoptions "github.com/falcosecurity/falcoctl/pkg/options"
)

// NewArtifactCmd return the artifact command.
func NewArtifactCmd(ctx context.Context, opt *commonoptions.CommonOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:                   "artifact",
		DisableFlagsInUseLine: true,
		Short:                 "Interact with Falco artifacts",
		Long:                  "Interact with Falco artifacts",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			opt.Initialize()
			opt.Printer.CheckErr(config.Load(opt.ConfigFile))

			// add indexes if needed
			// Set up basic authentication
			indexes, err := config.Indexes()
			opt.Printer.CheckErr(err)

			// Create the index cache.
			indexCache, err := cache.NewFromConfig(ctx, config.IndexesFile, config.IndexesDir, indexes)
			opt.Printer.CheckErr(err)

			basicAuths, err := config.BasicAuths()
			opt.Printer.CheckErr(err)
			for _, basicAuth := range basicAuths {
				cred := &auth.Credential{
					Username: basicAuth.User,
					Password: basicAuth.Password,
				}

				opt.Printer.CheckErr(basic.DoLogin(ctx, basicAuth.Registry, cred))
			}

			oauthAuths, err := config.OauthAuths()
			opt.Printer.CheckErr(err)
			for _, auth := range oauthAuths {
				oauthMgr := oauth.RegistryOauthOptions{
					CommonOptions: opt,
					Conf: clientcredentials.Config{
						ClientID:     auth.ClientID,
						ClientSecret: auth.ClientSecret,
						TokenURL:     auth.TokenURL,
					},
				}
				opt.Printer.CheckErr(oauthMgr.RunOauth(ctx, []string{auth.Registry}))
			}

			opt.Initialize(commonoptions.WithIndexCache(indexCache))
		},
	}

	cmd.AddCommand(search.NewArtifactSearchCmd(ctx, opt))
	cmd.AddCommand(install.NewArtifactInstallCmd(ctx, opt))
	cmd.AddCommand(list.NewArtifactListCmd(ctx, opt))
	cmd.AddCommand(info.NewArtifactInfoCmd(ctx, opt))
	cmd.AddCommand(follow.NewArtifactFollowCmd(ctx, opt))

	return cmd
}
