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
	"golang.org/x/oauth2/clientcredentials"
	"oras.land/oras-go/v2/registry/remote/auth"

	"github.com/falcosecurity/falcoctl/internal/artifact/follow"
	"github.com/falcosecurity/falcoctl/internal/artifact/info"
	"github.com/falcosecurity/falcoctl/internal/artifact/install"
	"github.com/falcosecurity/falcoctl/internal/artifact/list"
	"github.com/falcosecurity/falcoctl/internal/artifact/search"
	"github.com/falcosecurity/falcoctl/internal/config"
	"github.com/falcosecurity/falcoctl/internal/index/add"
	"github.com/falcosecurity/falcoctl/internal/registry/auth/login"
	"github.com/falcosecurity/falcoctl/internal/registry/auth/oauth"
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

			for _, ind := range indexes {
				indexMgr := add.IndexAddOptions{
					CommonOptions: opt,
				}
				opt.Printer.CheckErr(indexMgr.Validate([]string{ind.Name, ind.URL}))
				opt.Printer.CheckErr(indexMgr.RunIndexAdd(ctx, []string{ind.Name, ind.URL}))
			}

			basicAuths, err := config.BasicAuths()
			opt.Printer.CheckErr(err)
			for _, basicAuth := range basicAuths {
				cred := &auth.Credential{
					Username: basicAuth.User,
					Password: basicAuth.Password,
				}

				opt.Printer.CheckErr(login.DoLogin(ctx, basicAuth.Registry, cred))
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
		},
	}

	cmd.AddCommand(search.NewArtifactSearchCmd(ctx, opt))
	cmd.AddCommand(install.NewArtifactInstallCmd(ctx, opt))
	cmd.AddCommand(list.NewArtifactListCmd(ctx, opt))
	cmd.AddCommand(info.NewArtifactInfoCmd(ctx, opt))
	cmd.AddCommand(follow.NewArtifactFollowCmd(ctx, opt))

	return cmd
}
