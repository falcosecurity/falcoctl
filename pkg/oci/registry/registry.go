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

package registry

import (
	"context"
	"fmt"
	"github.com/falcosecurity/falcoctl/pkg/oci/authn"
	"oras.land/oras-go/v2/registry/remote"
)

// Registry is an HTTP client to interact with a remote registry.
type Registry struct {
	*remote.Registry
}

// NewRegistry returns a new Registry.
//
// Return an error if the given ref is not valid.
func NewRegistry(ref string, options ...func(*Registry)) (*Registry, error) {
	registry := &Registry{}
	var err error

	registry.Registry, err = remote.NewRegistry(ref)
	if err != nil {
		return nil, fmt.Errorf("unable to create new repository with ref %s: %w", ref, err)
	}

	for _, o := range options {
		o(registry)
	}

	return registry, nil
}

// WithClient sets the underlying HTTP client to be used for requests.
func WithClient(client *authn.Client) func(r *Registry) {
	return func(r *Registry) {
		r.Client = client
	}
}

// WithPlainHTTP specifies if requests should be done in plain http.
func WithPlainHTTP(plainHTTP bool) func(r *Registry) {
	return func(r *Registry) {
		r.PlainHTTP = plainHTTP
	}
}

// CheckConnection checks whether the underlying HTTP client can correctly interact with the remote registry.
func (r *Registry) CheckConnection(ctx context.Context) error {
	return r.Registry.Ping(ctx)
}
