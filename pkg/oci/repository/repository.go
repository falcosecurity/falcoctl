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

package repository

import (
	"fmt"

	"oras.land/oras-go/v2/registry/remote"

	"github.com/falcosecurity/falcoctl/pkg/oci/authn"
)

// Repository is an HTTP client to interact with a remote repository.
type Repository struct {
	*remote.Repository
}

// NewRepository returns a new Repository.
//
// Return an error if the given ref is not valid.
func NewRepository(ref string, options ...func(*Repository)) (*Repository, error) {
	repo := &Repository{}
	var err error

	repo.Repository, err = remote.NewRepository(ref)
	if err != nil {
		return nil, fmt.Errorf("unable to create new repository with ref %s: %w", ref, err)
	}

	for _, o := range options {
		o(repo)
	}

	return repo, nil
}

// WithClient sets the underlying HTTP client to be used for requests.
func WithClient(client *authn.Client) func(r *Repository) {
	return func(r *Repository) {
		r.Client = client
	}
}

// WithPlainHTTP specifies if requests should be done in plain http.
func WithPlainHTTP(plainHTTP bool) func(r *Repository) {
	return func(r *Repository) {
		r.PlainHTTP = plainHTTP
	}
}
