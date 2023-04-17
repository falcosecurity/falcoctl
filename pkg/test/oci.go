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

package test

import (
	"encoding/json"
	"fmt"
	"io"

	v1 "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/falcosecurity/falcoctl/pkg/oci"
)

// ManifestFromReader extracts a v1.Manifest from a reader.
func ManifestFromReader(descReader io.Reader) (*v1.Manifest, error) {
	var manifest v1.Manifest
	descBytes, err := io.ReadAll(descReader)
	if err != nil {
		return nil, fmt.Errorf("unable to read bytes from descriptor: %w", err)
	}

	if err = json.Unmarshal(descBytes, &manifest); err != nil {
		return nil, fmt.Errorf("unable to unmarshal manifest: %w", err)
	}

	return &manifest, nil
}

// ImageIndexFromReader extracts v1.Index from a reader.
func ImageIndexFromReader(descReader io.Reader) (*v1.Index, error) {
	var index v1.Index
	descBytes, err := io.ReadAll(descReader)
	if err != nil {
		return nil, fmt.Errorf("unable to read bytes from descriptor: %w", err)
	}

	if err = json.Unmarshal(descBytes, &index); err != nil {
		return nil, fmt.Errorf("unable to unmarshal manifest: %w", err)
	}

	return &index, nil
}

// DependenciesFromReader extracts oci.ArtifactConfig from a reader.
func DependenciesFromReader(descReader io.Reader) (*oci.ArtifactConfig, error) {
	var dep oci.ArtifactConfig
	descBytes, err := io.ReadAll(descReader)
	if err != nil {
		if err != nil {
			return nil, fmt.Errorf("unable to read bytes from descriptor: %w", err)
		}
	}
	if err = json.Unmarshal(descBytes, &dep); err != nil {
		return nil, fmt.Errorf("unable to unmarshal dependencies: %w", err)
	}

	return &dep, nil
}
