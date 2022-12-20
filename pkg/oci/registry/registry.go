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
	"net/http"
	"reflect"

	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
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
		return nil, fmt.Errorf("unable to create new registry with ref %s: %w", ref, err)
	}

	for _, o := range options {
		o(registry)
	}

	return registry, nil
}

// WithClient sets the underlying HTTP client to be used for requests.
func WithClient(client remote.Client) func(r *Registry) {
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
	if authClient, ok := r.Client.(*auth.Client); ok {
		cred, err := authClient.Credential(ctx, r.RepositoryOptions.Reference.Registry)
		if err != nil {
			return err
		}
		if reflect.DeepEqual(cred, auth.EmptyCredential) {
			if err := r.checkConnectionUnauthenticated(ctx); err != nil {
				return err
			}
			return nil
		}
	}
	return r.Registry.Ping(ctx)
}

func (r *Registry) checkConnectionUnauthenticated(ctx context.Context) error {
	regName := r.RepositoryOptions.Reference.Registry
	var url string
	if r.PlainHTTP {
		url = fmt.Sprintf("http://%s/v2/", regName)
	} else {
		url = fmt.Sprintf("https://%s/v2/", regName)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK, http.StatusUnauthorized:
		// We are just checking if the V2 endpoint exists. Do not care about authorization/authentication.
		if registry, ok := resp.Header[http.CanonicalHeaderKey("Docker-Distribution-API-Version")]; ok {
			if len(registry) > 0 && registry[0] == "registry/2.0" {
				return nil
			}
		}
		return fmt.Errorf("remote registry %q does not implement Docker Registry HTTP API V2: %q", url, resp.Status)
	default:
		return fmt.Errorf("unable to check remote registry %q: %q", url, resp.Status)
	}
}
