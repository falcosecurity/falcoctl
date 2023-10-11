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

package authn

import (
	"context"
	"fmt"

	"golang.org/x/oauth2"
	"oras.land/oras-go/v2/registry/remote/auth"

	"github.com/falcosecurity/falcoctl/internal/config"
)

// OAuthClientCredentialsStore provides credential retrieval for oauth client credentials.
type OAuthClientCredentialsStore struct {
	OAuth2TokenSources map[string]oauth2.TokenSource
}

// NewOauthClientCredentialsStore creates a new OAuth client credential store.
func NewOauthClientCredentialsStore() OAuthClientCredentialsStore {
	return OAuthClientCredentialsStore{
		OAuth2TokenSources: make(map[string]oauth2.TokenSource),
	}
}

// Credential retrieves a valid access token auth credential for the given registry.
func (o *OAuthClientCredentialsStore) Credential(ctx context.Context, reg string) (auth.Credential, error) {
	tokenSource, exists := o.OAuth2TokenSources[reg]
	// if we did not already load a token source for this registry check the client credential file
	if !exists {
		clientCreds, err := config.ClientCredentials(reg)
		if err != nil {
			return auth.EmptyCredential, fmt.Errorf("unable to retrieve client credentials %w", err)
		}

		if clientCreds != nil {
			tokenSource = clientCreds.TokenSource(ctx)
		}
		// cache nil result as well to avoid reading creds file every time we check for the registry
		o.OAuth2TokenSources[reg] = tokenSource
	}

	if tokenSource == nil {
		return auth.EmptyCredential, nil
	}

	token, err := tokenSource.Token()
	if err != nil {
		return auth.EmptyCredential, err
	}

	return auth.Credential{
		RefreshToken: token.RefreshToken,
		AccessToken:  token.AccessToken,
	}, nil
}
