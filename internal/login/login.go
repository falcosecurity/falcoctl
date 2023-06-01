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

	credentials "github.com/oras-project/oras-credentials-go"
	"golang.org/x/oauth2/clientcredentials"
	"oras.land/oras-go/v2/registry/remote/auth"

	"github.com/falcosecurity/falcoctl/internal/config"
	"github.com/falcosecurity/falcoctl/internal/login/basic"
	"github.com/falcosecurity/falcoctl/internal/login/oauth"
)

// PerformAuthsFromConfig logins to the specified registries and stores credentials in local stores.
func PerformAuthsFromConfig(ctx context.Context, client *auth.Client, credStore credentials.Store, registries []string) error {
	registrySet := make(map[string]bool)
	for _, reg := range registries {
		registrySet[reg] = true
	}

	return PerformAuthsFromConfigWithMap(ctx, client, credStore, registrySet)
}

// PerformAuthsFromConfigWithMap logins to the specified registry set and stores credentials in local stores.
func PerformAuthsFromConfigWithMap(ctx context.Context, client *auth.Client, credStore credentials.Store, registrySet map[string]bool) error {
	// Perform authentications using basic auth.
	basicAuths, err := config.BasicAuths()
	if err != nil {
		return err
	}

	// skip basic auth login if we do not have a credentials.Store
	if credStore != nil {
		if err := PerformBasicAuthsLogin(ctx, client, credStore, basicAuths, registrySet); err != nil {
			return err
		}
	}

	// Perform authentications using oauth auth.
	oauthAuths, err := config.OauthAuths()
	if err != nil {
		return err
	}

	return PerformOauthAuths(ctx, oauthAuths, registrySet)
}

// PerformBasicAuthsLogin logins to the registries using basic auth and stores the credentials in a local store.
func PerformBasicAuthsLogin(
	ctx context.Context, client *auth.Client, credStore credentials.Store, auths []config.BasicAuth, registrySet map[string]bool,
) error {
	for _, basicAuth := range auths {
		if _, exists := registrySet[basicAuth.Registry]; exists {
			if err := basic.Login(ctx, client, credStore, basicAuth.Registry, basicAuth.User, basicAuth.Password); err != nil {
				return err
			}
		}
	}

	return nil
}

// PerformOauthAuths logins to the registries using oauth client credentials and stores the credentials in a local store.
func PerformOauthAuths(ctx context.Context, auths []config.OauthAuth, registrySet map[string]bool) error {
	for _, auth := range auths {
		if _, exists := registrySet[auth.Registry]; exists {
			creds := &clientcredentials.Config{
				ClientID:     auth.ClientID,
				ClientSecret: auth.ClientSecret,
				TokenURL:     auth.TokenURL,
			}
			if err := oauth.Login(ctx, auth.Registry, creds); err != nil {
				return err
			}
		}
	}

	return nil
}
