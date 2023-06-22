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

package authn

import (
	"context"
	"fmt"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"oras.land/oras-go/v2/registry/remote/auth"

	"github.com/falcosecurity/falcoctl/internal/config"
)

// GkeClientCredentialsStore provides credential retrieval for gke client credentials.
type GkeClientCredentialsStore struct {
	Gke2TokenSources map[string]oauth2.TokenSource
}

// NewOauthClientCredentialsStore creates a new Gke client credential store.
func NewGkeClientCredentialsStore() GkeClientCredentialsStore {
	return GkeClientCredentialsStore{
		Gke2TokenSources: make(map[string]oauth2.TokenSource),
	}
}

// Credential retrieves a valid access token auth credential for the given registry.
func (o *GkeClientCredentialsStore) Credential(ctx context.Context, reg string) (auth.Credential, error) {
	tokenSource, exists := o.Gke2TokenSources[reg]
	// if we did not already load a token source for this registry check the config file
	if !exists {
		gkeAuths, err := config.Gkes()
		if err != nil {
			return auth.EmptyCredential, fmt.Errorf("unable to retrieve gke credentials %w", err)
		}

		for _, gke := range gkeAuths {
			if gke.Registry == reg {
				tokenSource, err = google.DefaultTokenSource(ctx)
				if err != nil {
					return auth.EmptyCredential, fmt.Errorf("wrong gke source, unable to find a valid source: %w", err)
				}
			}

		}
		// cache nil result as well to avoid reading creds file every time we check for the registry
		o.Gke2TokenSources[reg] = tokenSource
	}

	if tokenSource == nil {
		return auth.EmptyCredential, nil
	}

	token, err := tokenSource.Token()
	if err != nil {
		return auth.EmptyCredential, err
	}

	return auth.Credential{
		Username: "oauth2accesstoken",
		Password: token.AccessToken,
	}, nil
}
