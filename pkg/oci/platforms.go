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

package oci

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/registry/remote"

	"github.com/falcosecurity/falcoctl/pkg/oci/repository"
)

// Platforms returns a list of all available platforms for a given ref.
func Platforms(ctx context.Context, ref string, client remote.Client) (map[string]struct{}, error) {
	repo, err := repository.NewRepository(ref, repository.WithClient(client))
	if err != nil {
		return nil, err
	}

	refDesc, _, err := repo.FetchReference(ctx, ref)
	if err != nil {
		return nil, err
	}

	if refDesc.MediaType != v1.MediaTypeImageIndex {
		return nil, fmt.Errorf("reference does not point to an index")
	}

	indexReader, err := repo.Fetch(ctx, refDesc)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch descriptor: %w", err)
	}

	indexBytes, err := io.ReadAll(indexReader)
	if err != nil {
		return nil, err
	}

	var index v1.Index
	if err = json.Unmarshal(indexBytes, &index); err != nil {
		return nil, fmt.Errorf("unable to unmarshal index: %w", err)
	}

	platforms := make(map[string]struct{})
	for _, manifest := range index.Manifests {
		platform := manifest.Platform.OS + "-" + manifest.Platform.Architecture
		platforms[platform] = struct{}{}
	}

	return platforms, nil
}
