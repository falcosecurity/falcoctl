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

	"golang.org/x/exp/slices"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"oras.land/oras-go/v2/registry/remote/auth"

	"github.com/falcosecurity/falcoctl/internal/config"
)

const (
	// UsernameAccessToken is the valid username for Artifact Registry authentication with an access token
	// See https://cloud.google.com/artifact-registry/docs/docker/authentication#token
	UsernameAccessToken = "oauth2accesstoken"
)

var (
	// SavedTokenSource saved for all registries using gcp credentials.
	SavedTokenSource oauth2.TokenSource
)

// GCPCredential retrieves a valid access token from gcp source to perform registry authentication.
func GCPCredential(ctx context.Context, reg string) (auth.Credential, error) {
	var tokenSource oauth2.TokenSource
	gcpAuths, err := config.Gcps()
	if err != nil {
		return auth.EmptyCredential, fmt.Errorf("unable to retrieve gcp authentication config %w", err)
	}

	idx := slices.IndexFunc(gcpAuths, func(c config.GcpAuth) bool { return c.Registry == reg })

	// gcp auth not set for this registry
	if idx == -1 {
		return auth.EmptyCredential, nil
	}

	// load saved tokenSource or saves it
	if SavedTokenSource == nil {
		tokenSource, err = google.DefaultTokenSource(ctx)
		if err != nil {
			return auth.EmptyCredential, fmt.Errorf("error while trying to identify a GCP TokenSource %w", err)
		}
		if tokenSource == nil {
			return auth.EmptyCredential, fmt.Errorf("wrong GCP source, unable to find a valid TokenSource: %w", err)
		}
		tokenSource = oauth2.ReuseTokenSource(nil, tokenSource)
		SavedTokenSource = tokenSource
	} else {
		tokenSource = SavedTokenSource
	}

	token, err := tokenSource.Token()
	if err != nil {
		return auth.EmptyCredential, err
	}

	return auth.Credential{
		Username: UsernameAccessToken,
		Password: token.AccessToken,
	}, nil
}
