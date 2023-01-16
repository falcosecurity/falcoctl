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

package utils

import (
	"context"
	"fmt"
	"reflect"

	"golang.org/x/oauth2/clientcredentials"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"

	"github.com/falcosecurity/falcoctl/pkg/oci/authn"
	ocipuller "github.com/falcosecurity/falcoctl/pkg/oci/puller"
	ocipusher "github.com/falcosecurity/falcoctl/pkg/oci/pusher"
	"github.com/falcosecurity/falcoctl/pkg/oci/registry"
	"github.com/falcosecurity/falcoctl/pkg/output"
)

// PullerForRegistry returns a new ocipuller.Puller ready to be used for the given registry.
func PullerForRegistry(ctx context.Context, reg string, plainHTTP bool, printer *output.Printer) (*ocipuller.Puller, error) {
	client, err := ClientForRegistry(ctx, reg, plainHTTP, printer)
	if err != nil {
		return nil, err
	}

	return ocipuller.NewPuller(client, plainHTTP, output.NewTracker(printer, "Pulling")), nil
}

// PusherForRegistry returns ane ocipusher.Pusher ready to be used for the given registry.
func PusherForRegistry(ctx context.Context, plainHTTP bool, reg string, printer *output.Printer) (*ocipusher.Pusher, error) {
	client, err := ClientForRegistry(ctx, reg, plainHTTP, printer)
	if err != nil {
		return nil, err
	}
	return ocipusher.NewPusher(client, plainHTTP, output.NewTracker(printer, "Pushing")), nil
}

// ClientForRegistry returns a new auth.Client for the given registry.
// It authenticates the client if credentials are found in the system.
func ClientForRegistry(ctx context.Context, reg string, plainHTTP bool, printer *output.Printer) (remote.Client, error) {
	var cred auth.Credential
	var conf *clientcredentials.Config
	var err error
	var oauth bool

	// Check if we logged in with basic auth first
	credentialStore, err := authn.NewStore([]string{}...)
	if err != nil {
		return nil, fmt.Errorf("unable to create new store: %w", err)
	}

	printer.Verbosef("Retrieving credentials from local store")
	cred, err = credentialStore.Credential(ctx, reg)
	if err != nil {
		return nil, fmt.Errorf("error retrieving credentials for registry %s: %w", reg, err)
	}

	// Try client credentials
	if reflect.DeepEqual(cred, auth.EmptyCredential) {
		regCred, err := ClientCredentials(reg)
		if err != nil {
			return nil, fmt.Errorf("unexpected error while reading client credentials: %w", err)
		}

		if regCred != nil {
			printer.Verbosef("proceeding with client credentials credentials for registry %q", reg)
			oauth = true
			conf = regCred
		} else {
			printer.Verbosef("proceeding with empty credentials for registry %q", reg)
		}

	} else {
		printer.Verbosef("found basic credentials for registry %q", reg)
	}

	client := authn.NewClient(
		authn.WithClientCredentials(conf),
		authn.WithOauth(ctx, oauth),
		authn.WithCredentials(&cred))

	r, err := registry.NewRegistry(reg, registry.WithClient(client), registry.WithPlainHTTP(plainHTTP))
	if err != nil {
		return nil, fmt.Errorf("unable to create registry: %w", err)
	}

	if err := r.CheckConnection(ctx); err != nil {
		return nil, fmt.Errorf("unable to connect to remote registry %q: %w", reg, err)
	}

	return client, nil
}
