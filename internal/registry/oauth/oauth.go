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
	"golang.org/x/oauth2/clientcredentials"

	"github.com/falcosecurity/falcoctl/internal/config"
	"github.com/falcosecurity/falcoctl/internal/utils"
	"github.com/falcosecurity/falcoctl/pkg/options"
)

const (
	longOauth = `Store client credentials for later OAuth2.0 authentication

Client credentials will be saved in the ~/.config directory.

Example 
	falcoctl registry oauth \
		--token-url="http://localhost:9096/token" \
		--client-id=000000 \
		--client-secret=999999  --scopes="my-scope"
`
)

type oauthOptions struct {
	*options.CommonOptions
	conf clientcredentials.Config
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

	cmd.Flags().StringVar(&o.conf.TokenURL, "token-url", "", "token URL used to get access and refresh tokens")
	if err := cmd.MarkFlagRequired("token-url"); err != nil {
		o.Printer.Error.Println("unable to mark flag \"token-url\" as required")
		return nil
	}
	cmd.Flags().StringVar(&o.conf.ClientID, "client-id", "", "client ID of the OAuth2.0 app")
	if err := cmd.MarkFlagRequired("client-id"); err != nil {
		o.Printer.Error.Println("unable to mark flag \"client-id\" as required")
		return nil
	}
	cmd.Flags().StringVar(&o.conf.ClientSecret, "client-secret", "", "client secret of the OAuth2.0 app")
	if err := cmd.MarkFlagRequired("client-secret"); err != nil {
		o.Printer.Error.Println("unable to mark flag \"client-secret\" as required")
		return nil
	}
	cmd.Flags().StringSliceVar(&o.conf.Scopes, "scopes", nil, "comma separeted list of scopes for which requesting access")

	return cmd
}

func (o *oauthOptions) RunOauth(ctx context.Context) error {
	// Check that we can retrieve token using the passed credentials.
	_, err := o.conf.Token(ctx)
	if err != nil {
		return fmt.Errorf("wrong client credentials, unable to retrieve token: %w", err)
	}

	// Save client credentials to file.
	if err = utils.WriteClientCredentials(&o.conf); err != nil {
		return fmt.Errorf("unable to save token: %w", err)
	}

	o.Printer.Success.Printfln("client credentials correctly saved in %q", config.ClientCredentialsFile)

	return nil
}
