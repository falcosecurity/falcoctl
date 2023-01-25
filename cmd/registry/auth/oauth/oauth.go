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
		--client-secret=999999  --scopes="my-scope" \ 
		hostname
`
)

// RegistryOauthOptions contains the options for the registry oauth command.
type RegistryOauthOptions struct {
	*options.CommonOptions
	Conf clientcredentials.Config
}

// NewOauthCmd returns the oauth command.
func NewOauthCmd(ctx context.Context, opt *options.CommonOptions) *cobra.Command {
	o := RegistryOauthOptions{
		CommonOptions: opt,
	}

	cmd := &cobra.Command{
		Use:                   "oauth [HOSTNAME]",
		DisableFlagsInUseLine: true,
		Short:                 "Retrieve access and refresh tokens for OAuth2.0 client credentials flow authentication",
		Long:                  longOauth,
		Args:                  cobra.ExactArgs(1),
		PreRun: func(cmd *cobra.Command, args []string) {
			opt.Initialize()
			opt.Printer.CheckErr(config.Load(opt.ConfigFile))
		},
		Run: func(cmd *cobra.Command, args []string) {
			o.Printer.CheckErr(o.RunOauth(ctx, args))
		},
	}

	cmd.Flags().StringVar(&o.Conf.TokenURL, "token-url", "", "token URL used to get access and refresh tokens")
	if err := cmd.MarkFlagRequired("token-url"); err != nil {
		o.Printer.Error.Println("unable to mark flag \"token-url\" as required")
		return nil
	}
	cmd.Flags().StringVar(&o.Conf.ClientID, "client-id", "", "client ID of the OAuth2.0 app")
	if err := cmd.MarkFlagRequired("client-id"); err != nil {
		o.Printer.Error.Println("unable to mark flag \"client-id\" as required")
		return nil
	}
	cmd.Flags().StringVar(&o.Conf.ClientSecret, "client-secret", "", "client secret of the OAuth2.0 app")
	if err := cmd.MarkFlagRequired("client-secret"); err != nil {
		o.Printer.Error.Println("unable to mark flag \"client-secret\" as required")
		return nil
	}
	cmd.Flags().StringSliceVar(&o.Conf.Scopes, "scopes", nil, "comma separeted list of scopes for which requesting access")

	return cmd
}

// RunOauth implements the registry oauth command.
func (o *RegistryOauthOptions) RunOauth(ctx context.Context, args []string) error {
	reg := args[0]

	// Check that we can retrieve token using the passed credentials.
	_, err := o.Conf.Token(ctx)
	if err != nil {
		return fmt.Errorf("wrong client credentials, unable to retrieve token: %w", err)
	}

	// Save client credentials to file.
	if err = utils.WriteClientCredentials(reg, &o.Conf); err != nil {
		return fmt.Errorf("unable to save token: %w", err)
	}

	currentAuths, err := config.OauthAuths()
	if err != nil {
		return fmt.Errorf("unable to get oauthAuths from viper: %w", err)
	}

	for _, a := range currentAuths {
		if a.Registry == reg {
			o.Printer.Verbosef("credentials for registry %q already exists in the config file %q", reg, config.ConfigPath)
			return nil
		}
	}

	currentAuths = append(currentAuths, config.OauthAuth{
		Registry:     reg,
		ClientSecret: o.Conf.ClientSecret,
		ClientID:     o.Conf.ClientID,
		TokenURL:     o.Conf.TokenURL,
	})

	if err := config.UpdateConfigFile(config.RegistryAuthOauthKey, currentAuths, o.ConfigFile); err != nil {
		return fmt.Errorf("unable to update oauth auths credential list in the config file %q: %w", config.ConfigPath, err)
	}
	o.Printer.Verbosef("credentials added to config file %q", config.ConfigPath)

	o.Printer.Success.Printfln("client credentials correctly saved in %q", config.ClientCredentialsFile)

	return nil
}
