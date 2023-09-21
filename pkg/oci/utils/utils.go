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

package utils

import (
	"context"
	"fmt"

	credentials "github.com/oras-project/oras-credentials-go"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"

	"github.com/falcosecurity/falcoctl/internal/config"
	"github.com/falcosecurity/falcoctl/pkg/oci/authn"
	ocipuller "github.com/falcosecurity/falcoctl/pkg/oci/puller"
	ocipusher "github.com/falcosecurity/falcoctl/pkg/oci/pusher"
	"github.com/falcosecurity/falcoctl/pkg/oci/registry"
	"github.com/falcosecurity/falcoctl/pkg/output"
)

// Puller returns a new ocipuller.Puller ready to be used for pulling from oci registries.
func Puller(plainHTTP bool, printer *output.Printer) (*ocipuller.Puller, error) {
	client, err := Client(true)
	if err != nil {
		return nil, err
	}

	return ocipuller.NewPuller(client, plainHTTP, output.NewTracker(printer, "Pulling")), nil
}

// Pusher returns an ocipusher.Pusher ready to be used for pushing to oci registries.
func Pusher(plainHTTP bool, printer *output.Printer) (*ocipusher.Pusher, error) {
	client, err := Client(true)
	if err != nil {
		return nil, err
	}
	return ocipusher.NewPusher(client, plainHTTP, output.NewTracker(printer, "Pushing")), nil
}

// Client returns a new auth.Client.
// It authenticates the client if credentials are found in the system.
func Client(enableClientTokenCache bool) (remote.Client, error) {
	credentialStore, err := credentials.NewStore(config.RegistryCredentialConfPath(), credentials.StoreOptions{
		AllowPlaintextPut: true,
	})
	if err != nil {
		return nil, fmt.Errorf("unable to create new store: %w", err)
	}

	// create client that
	// 1. auto logins into registries
	// 2. checks basic auth credential store
	// 3. checks oauth2 clientcredentials
	// 4. checks gcp credentials if enabled
	ops := []func(*authn.Options){
		authn.WithAutoLogin(authn.NewAutoLoginHandler(credentialStore)),
		authn.WithStore(credentialStore),
		authn.WithOAuthCredentials(),
		authn.WithGcpCredentials(),
	}
	if enableClientTokenCache {
		ops = append(ops, authn.WithClientTokenCache(auth.NewCache()))
	}
	client := authn.NewClient(ops...)

	return client, nil
}

// CheckConnectionForRegistry validates the connection to an oci registry.
func CheckConnectionForRegistry(ctx context.Context, client remote.Client, plainHTTP bool, reg string) error {
	r, err := registry.NewRegistry(reg, registry.WithClient(client), registry.WithPlainHTTP(plainHTTP))
	if err != nil {
		return fmt.Errorf("unable to create registry: %w", err)
	}

	if err := r.CheckConnection(ctx); err != nil {
		return fmt.Errorf("unable to connect to remote registry %q: %w", reg, err)
	}

	return nil
}
