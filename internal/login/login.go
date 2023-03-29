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

package login

import (
	"context"

	"golang.org/x/oauth2/clientcredentials"
	"oras.land/oras-go/v2/registry/remote/auth"

	"github.com/falcosecurity/falcoctl/cmd/registry/auth/basic"
	"github.com/falcosecurity/falcoctl/cmd/registry/auth/oauth"
	"github.com/falcosecurity/falcoctl/internal/config"
	"github.com/falcosecurity/falcoctl/pkg/options"
)

// PerformBasicAuthsLogin logins to the registries and stores the credentials in a local store.
func PerformBasicAuthsLogin(ctx context.Context, auths []config.BasicAuth) error {
	for _, basicAuth := range auths {
		cred := &auth.Credential{
			Username: basicAuth.User,
			Password: basicAuth.Password,
		}
		if err := basic.DoLogin(ctx, basicAuth.Registry, cred); err != nil {
			return err
		}
	}

	return nil
}

// PerformOauthAuths logins to the registries and store the credentials in a  local store.
func PerformOauthAuths(ctx context.Context, opt *options.CommonOptions, auths []config.OauthAuth) error {
	for _, auth := range auths {
		oauthMgr := oauth.RegistryOauthOptions{
			CommonOptions: opt,
			Conf: clientcredentials.Config{
				ClientID:     auth.ClientID,
				ClientSecret: auth.ClientSecret,
				TokenURL:     auth.TokenURL,
			},
		}
		if err := oauthMgr.RunOauth(ctx, []string{auth.Registry}); err != nil {
			return err
		}
	}

	return nil
}
