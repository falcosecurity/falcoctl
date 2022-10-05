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

package oci

import (
	"context"

	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
)

// Tags returns the list of all available tags of an artifact given a reference to a repository.
func Tags(ctx context.Context, ref string, client *auth.Client) ([]string, error) {
	repository, err := remote.NewRepository(ref)
	if err != nil {
		return nil, err
	}
	repository.Client = client

	var result []string
	var tagRetriever = func(tags []string) error {
		result = tags
		return nil
	}

	err = repository.Tags(ctx, "", tagRetriever)
	if err != nil {
		return nil, err
	}

	return result, nil
}
