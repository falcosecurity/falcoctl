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

package oauth

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	"golang.org/x/oauth2/clientcredentials"

	"github.com/falcosecurity/falcoctl/internal/config"
	"github.com/falcosecurity/falcoctl/internal/login/oauth"
	"github.com/falcosecurity/falcoctl/pkg/options"
	"github.com/falcosecurity/falcoctl/pkg/output"
)

const (
	longOauth = `Store client credentials for later OAuth2.0 authentication

Client credentials will be saved in the ~/.config directory.

Example
	falcoctl registry oauth \
		--token-url="http://localhost:9096/token" \
		--client-id=000000 \
		--client-secret=999999  --scopes="my-scope" \
		hostname
`
)

// RegistryOauthOptions contains the options for the registry oauth command.
type RegistryOauthOptions struct {
	*options.Common
	Conf clientcredentials.Config
}

// NewOauthCmd returns the oauth command.
func NewOauthCmd(ctx context.Context, opt *options.Common) *cobra.Command {
	o := RegistryOauthOptions{
		Common: opt,
	}

	cmd := &cobra.Command{
		Use:                   "oauth [HOSTNAME]",
		DisableFlagsInUseLine: true,
		Short:                 "Retrieve access and refresh tokens for OAuth2.0 client credentials flow authentication",
		Long:                  longOauth,
		Args:                  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return o.RunOAuth(ctx, args)
		},
	}

	cmd.Flags().StringVar(&o.Conf.TokenURL, "token-url", "", "token URL used to get access and refresh tokens")
	if err := cmd.MarkFlagRequired("token-url"); err != nil {
		output.ExitOnErr(o.Printer, fmt.Errorf("unable to mark flag \"token-url\" as required"))
	}
	cmd.Flags().StringVar(&o.Conf.ClientID, "client-id", "", "client ID of the OAuth2.0 app")
	if err := cmd.MarkFlagRequired("client-id"); err != nil {
		output.ExitOnErr(o.Printer, fmt.Errorf("unable to mark flag \"client-id\" as required"))
	}
	cmd.Flags().StringVar(&o.Conf.ClientSecret, "client-secret", "", "client secret of the OAuth2.0 app")
	if err := cmd.MarkFlagRequired("client-secret"); err != nil {
		output.ExitOnErr(o.Printer, fmt.Errorf("unable to mark flag \"client-secret\" as required"))
		return nil
	}
	cmd.Flags().StringSliceVar(&o.Conf.Scopes, "scopes", nil, "comma separeted list of scopes for which requesting access")

	return cmd
}

// RunOAuth executes the business logic for the oauth command.
func (o *RegistryOauthOptions) RunOAuth(ctx context.Context, args []string) error {
	reg := args[0]
	if err := oauth.Login(ctx, reg, &o.Conf); err != nil {
		return err
	}
	o.Printer.Logger.Info("Client credentials correctly saved", o.Printer.Logger.Args("file", config.ClientCredentialsFile))
	return nil
}
