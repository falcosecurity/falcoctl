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

	"github.com/falcosecurity/falcoctl/pkg/oci/authn"
	ocipuller "github.com/falcosecurity/falcoctl/pkg/oci/puller"
	ocipusher "github.com/falcosecurity/falcoctl/pkg/oci/pusher"
	"github.com/falcosecurity/falcoctl/pkg/output"
)

// PullerForRegistry returns a new ocipuller.Puller ready to be used for the given registry.
func PullerForRegistry(ctx context.Context, registry string, printer *output.Printer) (*ocipuller.Puller, error) {
	client, err := ClientForRegistry(ctx, registry, printer)
	if err != nil {
		return nil, err
	}

	return ocipuller.NewPuller(client, output.NewTracker(printer, "Pulling")), nil
}

// PusherForRegistry returns ane ocipusher.Pusher ready to be used for the given registry.
func PusherForRegistry(ctx context.Context, plainHTTP bool, registry string, printer *output.Printer) (*ocipusher.Pusher, error) {
	client, err := ClientForRegistry(ctx, registry, printer)
	if err != nil {
		return nil, err
	}
	return ocipusher.NewPusher(client, plainHTTP, output.NewTracker(printer, "Pushing")), nil
}

// ClientForRegistry returns a new auth.Client for the given registry.
// It authenticates the client if credentials are found in the system.
func ClientForRegistry(ctx context.Context, registry string, printer *output.Printer) (*authn.Client, error) {
	credentialStore, err := authn.NewStore([]string{}...)
	if err != nil {
		return nil, fmt.Errorf("unable to create new store: %w", err)
	}

	printer.Verbosef("Retrieving credentials from local store")
	cred, err := credentialStore.Credential(ctx, registry)
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve credentials for registry %s: %w", registry, err)
	}

	if err := CheckRegistryConnection(ctx, &cred, registry, printer); err != nil {
		printer.Verbosef("%s", err.Error())
		return nil, fmt.Errorf("unable to connect to registry %q: %w", registry, err)
	}

	return authn.NewClient(authn.WithCredentials(&cred)), err
}
