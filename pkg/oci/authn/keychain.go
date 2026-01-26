// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The Falco Authors
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

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/v1/google"
	"golang.org/x/exp/slices"
	"oras.land/oras-go/v2/registry/remote/credentials"

	"github.com/falcosecurity/falcoctl/internal/config"
)

// Keychain implements authn.Keychain using the same authentication
// sources that falcoctl uses for pulling artifacts:
// 1. Falcoctl credential store (from falcoctl registry auth basic).
// 2. OAuth2 client credentials (from falcoctl's config).
// 3. GCP credentials (for registries configured with falcoctl registry auth gcp).
type Keychain struct {
	credentialStore credentials.Store
	oauthStore      OAuthClientCredentialsStore
}

// NewKeychain creates a new keychain that uses falcoctl's authentication sources.
func NewKeychain() (*Keychain, error) {
	credentialStore, err := NewCredentialStore()
	if err != nil {
		return nil, err
	}

	return &Keychain{
		credentialStore: credentialStore,
		oauthStore:      NewOauthClientCredentialsStore(),
	}, nil
}

// Resolve implements authn.Keychain.
func (k *Keychain) Resolve(resource authn.Resource) (authn.Authenticator, error) {
	ctx := context.Background()
	registry := resource.RegistryStr()

	// 1. Try credential store (from falcoctl registry auth basic)
	cred, err := k.credentialStore.Get(ctx, registry)
	if err == nil && (cred.Username != "" || cred.AccessToken != "") {
		if cred.AccessToken != "" {
			return authn.FromConfig(authn.AuthConfig{
				RegistryToken: cred.AccessToken,
			}), nil
		}
		return authn.FromConfig(authn.AuthConfig{
			Username: cred.Username,
			Password: cred.Password,
		}), nil
	}

	// 2. Try OAuth2 client credentials
	oauthCred, err := k.oauthStore.Credential(ctx, registry)
	if err == nil && oauthCred.AccessToken != "" {
		return authn.FromConfig(authn.AuthConfig{
			RegistryToken: oauthCred.AccessToken,
		}), nil
	}

	// 3. Try GCP credentials (for registries configured with falcoctl registry auth gcp)
	if isGCPRegistry(registry) {
		return google.Keychain.Resolve(resource)
	}

	// No credentials found
	return authn.Anonymous, nil
}

// isGCPRegistry checks if the registry is configured for GCP authentication
// in falcoctl's configuration (via falcoctl registry auth gcp).
func isGCPRegistry(registry string) bool {
	gcpAuths, err := config.Gcps()
	if err != nil {
		return false
	}

	idx := slices.IndexFunc(gcpAuths, func(c config.GcpAuth) bool {
		return c.Registry == registry
	})

	return idx != -1
}
