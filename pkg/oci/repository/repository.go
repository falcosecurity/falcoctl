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
	"context"
	"fmt"

	"github.com/blang/semver"
	"oras.land/oras-go/v2/registry/remote"
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
func WithClient(client remote.Client) func(r *Repository) {
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

// Tags returns the list of all available tags of an artifact given a reference to a repository.
func (r *Repository) Tags(ctx context.Context) ([]string, error) {
	var result []string
	var tagRetriever = func(tags []string) error {
		result = tags
		return nil
	}

	err := r.Repository.Tags(ctx, "", tagRetriever)
	if err != nil {
		return nil, err
	}

	result, err = sortTags(result)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func sortTags(tags []string) ([]string, error) {
	var parsedVersions []semver.Version
	var latest bool
	for _, t := range tags {
		if t == "latest" {
			latest = true
			continue
		}

		parsedVersion, err := semver.Parse(t)
		if err != nil {
			return nil, fmt.Errorf("cannot parse version %q", t)
		}

		parsedVersions = append(parsedVersions, parsedVersion)
	}

	semver.Sort(parsedVersions)

	var result []string
	for _, parsedVersion := range parsedVersions {
		result = append(result, parsedVersion.String())
	}

	if latest {
		result = append(result, "latest")
	}

	return result, nil
}
