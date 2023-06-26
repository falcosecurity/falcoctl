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

	"golang.org/x/exp/slices"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"oras.land/oras-go/v2/registry/remote/auth"

	"github.com/falcosecurity/falcoctl/internal/config"
)

var (
	// SavedTokenSource saved for all registries using gcp credentials.
	SavedTokenSource oauth2.TokenSource
)

// GKECredential retrieves a valid access token from gke source to perform registry authentication.
func GKECredential(ctx context.Context, reg string) (auth.Credential, error) {
	var tokenSource oauth2.TokenSource
	gkeAuths, err := config.Gkes()
	if err != nil {
		return auth.EmptyCredential, fmt.Errorf("unable to retrieve gke authentication config %w", err)
	}

	idx := slices.IndexFunc(gkeAuths, func(c config.GkeAuth) bool { return c.Registry == reg })

	// gke auth not set for this registry
	if idx == -1 {
		return auth.EmptyCredential, nil
	}

	// load saved tokenSource or saves it
	if SavedTokenSource != nil {
		tokenSource = SavedTokenSource
	} else {
		tokenSource, err = google.DefaultTokenSource(ctx)
		if err != nil {
			return auth.EmptyCredential, fmt.Errorf("wrong gke source, unable to find a valid source: %w", err)
		}
		if tokenSource == nil {
			return auth.EmptyCredential, fmt.Errorf("unable to retrieve gke credentials from identified source %w", err)
		}
		tokenSource = oauth2.ReuseTokenSource(nil, tokenSource)
		SavedTokenSource = tokenSource
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
