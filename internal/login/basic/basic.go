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

package basic

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/credentials"

	"github.com/falcosecurity/falcoctl/pkg/oci/registry"
)

// Login checks if passed credentials are correct and stores them.
func Login(ctx context.Context, client *auth.Client, credStore credentials.Store, reg, username, password string) error {
	cred := auth.Credential{
		Username: username,
		Password: password,
	}

	client.Credential = auth.StaticCredential(reg, cred)

	// Check if client is configured for insecure connections
	transport, ok := client.Client.Transport.(*http.Transport)
	insecure := ok && transport.TLSClientConfig != nil && transport.TLSClientConfig.InsecureSkipVerify

	// If the registry URL starts with https://, force HTTPS
	forceHTTPS := strings.HasPrefix(reg, "https://")
	// If the registry URL starts with http://, force HTTP
	forceHTTP := strings.HasPrefix(reg, "http://")
	// Strip scheme if present
	reg = strings.TrimPrefix(strings.TrimPrefix(reg, "http://"), "https://")

	// Create registry client with appropriate settings
	var r *registry.Registry
	var err error

	switch {
	case forceHTTPS:
		// For explicit HTTPS URLs, use HTTPS with insecure setting from client
		r, err = registry.NewRegistry(reg, registry.WithClient(client), registry.WithPlainHTTP(false))
	case forceHTTP:
		// For explicit HTTP URLs, use HTTP if insecure is enabled
		if !insecure {
			return fmt.Errorf("cannot use plain HTTP for %q without --insecure flag", reg)
		}
		r, err = registry.NewRegistry(reg, registry.WithClient(client), registry.WithPlainHTTP(true))
	default:
		// For URLs without scheme, try HTTPS first, then fall back to HTTP if insecure is enabled
		r, err = registry.NewRegistry(reg, registry.WithClient(client), registry.WithPlainHTTP(false))
		if err == nil {
			err = r.CheckConnection(ctx)
			if err != nil && insecure {
				// If HTTPS failed and insecure is enabled, try HTTP
				r, err = registry.NewRegistry(reg, registry.WithClient(client), registry.WithPlainHTTP(true))
			}
		}
	}

	if err != nil {
		return fmt.Errorf("unable to connect to registry %q: %w", reg, err)
	}

	if err := r.CheckConnection(ctx); err != nil {
		return fmt.Errorf("unable to connect to registry %q: %w", reg, err)
	}

	err = credStore.Put(ctx, reg, cred)
	if err != nil {
		return fmt.Errorf("unable to save credentials in credential store: %w", err)
	}
	return nil
}
