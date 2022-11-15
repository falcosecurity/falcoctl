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

package oauth

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"

	"github.com/falcosecurity/falcoctl/pkg/options"
)

const (
	longOauth = `Retrieve access and refresh tokens for OAuth2.0 client credentials flow authentication

With this command it is possible to interact with registries supporting OAuth2.0. 
This specific command implements the client credentials OAuh2.0 flow.

For more information, please visit:
https://www.rfc-editor.org/rfc/rfc6749#section-1.3

Example - Generate access and refresh tokens using "client_credentials" grant type:
	falcoctl registry oauth \
		--auth-url="http://localhost:9096/authorize" \
		--token-url="http://localhost:9096/token" \
		--client-id=000000 \
		--client-secret=999999  --scopes="my-scope"
`
)

type oauthOptions struct {
	*options.CommonOptions
	tokenURL     string
	clientID     string
	clientSecret string
	scopes       []string
}

// NewOauthCmd returns the oauth command.
func NewOauthCmd(ctx context.Context, opt *options.CommonOptions) *cobra.Command {
	o := oauthOptions{
		CommonOptions: opt,
	}

	cmd := &cobra.Command{
		Use:                   "oauth",
		DisableFlagsInUseLine: true,
		Short:                 "Retrieve access and refresh tokens for OAuth2.0 client credentials flow authentication",
		Long:                  longOauth,
		Args:                  cobra.ExactArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			o.Printer.CheckErr(o.RunOauth(ctx))
		},
	}

	cmd.Flags().StringVar(&o.tokenURL, "token-url", "", "token URL used to get access and refresh tokens")
	if err := cmd.MarkFlagRequired("token-url"); err != nil {
		o.Printer.Error.Println("unable to mark flag \"token-url\" as required")
		return nil
	}
	cmd.Flags().StringVar(&o.clientID, "client-id", "", "client ID of the OAuth2.0 app")
	if err := cmd.MarkFlagRequired("client-id"); err != nil {
		o.Printer.Error.Println("unable to mark flag \"client-id\" as required")
		return nil
	}
	cmd.Flags().StringVar(&o.clientSecret, "client-secret", "", "client secret of the OAuth2.0 app")
	if err := cmd.MarkFlagRequired("client-secret"); err != nil {
		o.Printer.Error.Println("unable to mark flag \"client-secret\" as required")
		return nil
	}
	cmd.Flags().StringSliceVar(&o.scopes, "scopes", nil, "comma separeted list of scopes for which requesting access")

	return cmd
}

func (o *oauthOptions) RunOauth(ctx context.Context) error {
	token, err := o.runOauthClientCredentials(ctx)
	if err != nil {
		return fmt.Errorf("unable to retrieve tokens: %w", err)
	}

	o.Printer.DefaultText.Printfln("access token: %s, refresh token: %s",
		token.AccessToken, token.RefreshToken)

	return nil
}

// runOauthClientCredentials implements the client_credentials flow.
func (o *oauthOptions) runOauthClientCredentials(ctx context.Context) (*oauth2.Token, error) {
	conf := clientcredentials.Config{
		ClientID:     o.clientID,
		ClientSecret: o.clientSecret,
		TokenURL:     o.tokenURL,
		Scopes:       o.scopes,
	}

	token, err := conf.Token(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve token: %w", err)
	}

	return token, nil
}
