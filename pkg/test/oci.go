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
	"context"
	"encoding/json"
	"fmt"
	"io"

	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/registry/remote"

	"github.com/falcosecurity/falcoctl/pkg/oci"
)

// Layer holds config and manifest for an artifact.
type Layer struct {
	Config   *oci.ArtifactConfig
	Manifest *v1.Manifest
}

// RulesfileArtifact holds OCI metadata for a rulesfile artifact.
type RulesfileArtifact struct {
	Descriptor *v1.Descriptor
	Layer      *Layer
	Tags       []string
}

// PluginArtifact holds OCI metadata for a plugin artifact.
type PluginArtifact struct {
	Descriptor *v1.Descriptor
	Index      *v1.Index
	Platforms  map[string]*Layer
	Tags       []string
}

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

// IndexFromReader extracts a v1.Index from a reader.
func IndexFromReader(descReader io.Reader) (*v1.Index, error) {
	var index v1.Index
	descBytes, err := io.ReadAll(descReader)
	if err != nil {
		return nil, fmt.Errorf("unable to read bytes from descriptor: %w", err)
	}

	if err = json.Unmarshal(descBytes, &index); err != nil {
		return nil, fmt.Errorf("unable to unmarshal index: %w", err)
	}

	return &index, nil
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

// NewOrasRegistry creates a registry to interact with a remote OCI registry.
func NewOrasRegistry(host string, plainHTTP bool) (*remote.Registry, error) {
	// Create the oras registry.
	reg, err := remote.NewRegistry(host)
	if err != nil {
		return nil, err
	}

	reg.PlainHTTP = plainHTTP

	return reg, nil
}

// FetchRulesfileFromRegistry fetches metadata for a plugin artifact.
func FetchRulesfileFromRegistry(ctx context.Context, ref, tag string, orasRegistry *remote.Registry) (*RulesfileArtifact, error) {
	var (
		reader     io.ReadCloser
		descriptor v1.Descriptor
		manifest   *v1.Manifest
		tags       []string
	)

	rf := &RulesfileArtifact{}

	// First thing create repository from registry
	repo, err := orasRegistry.Repository(ctx, ref)
	if err != nil {
		return nil, err
	}
	// Fetch descriptor.
	if descriptor, reader, err = repo.FetchReference(ctx, fmt.Sprintf("%s/%s:%s", orasRegistry.Reference.Registry, ref, tag)); err != nil {
		return nil, err
	}
	rf.Descriptor = &descriptor

	// Fetch manifest.
	if manifest, err = ManifestFromReader(reader); err != nil {
		return nil, err
	}

	// Fetch config.
	if reader, err = repo.Fetch(ctx, manifest.Config); err != nil {
		return nil, err
	}
	artifactCfg, err := DependenciesFromReader(reader)
	if err != nil {
		return nil, err
	}
	rf.Layer = &Layer{
		Config:   artifactCfg,
		Manifest: manifest,
	}

	// Fetch tags.
	if err = repo.Tags(ctx, "", func(t []string) error {
		tags = append(tags, t...)
		return nil
	}); err != nil {
		return nil, err
	}
	rf.Tags = tags

	return rf, nil
}

// FetchPluginFromRegistry fetches metadata for a plugin artifact.
func FetchPluginFromRegistry(ctx context.Context, ref, tag string, orasRegistry *remote.Registry) (*PluginArtifact, error) {
	var (
		reader     io.ReadCloser
		descriptor v1.Descriptor
		index      *v1.Index
		tags       []string
	)

	plugin := &PluginArtifact{
		Descriptor: nil,
		Index:      nil,
		Platforms:  make(map[string]*Layer),
		Tags:       nil,
	}

	// First thing create repository from registry
	repo, err := orasRegistry.Repository(ctx, ref)
	if err != nil {
		return nil, err
	}
	// Fetch descriptor.
	if descriptor, reader, err = repo.FetchReference(ctx, fmt.Sprintf("%s/%s:%s", orasRegistry.Reference.Registry, ref, tag)); err != nil {
		return nil, err
	}
	plugin.Descriptor = &descriptor

	// Fetch index.
	if index, err = IndexFromReader(reader); err != nil {
		return nil, err
	}
	plugin.Index = index

	// Fetch Platforms
	for _, m := range index.Manifests {
		var manifest *v1.Manifest
		var cfg *oci.ArtifactConfig
		reader, err = repo.Fetch(ctx, m)
		if err != nil {
			return nil, err
		}
		if manifest, err = ManifestFromReader(reader); err != nil {
			return nil, err
		}

		// Fetch the config.
		if reader, err = repo.Fetch(ctx, manifest.Config); err != nil {
			return nil, err
		}

		if cfg, err = DependenciesFromReader(reader); err != nil {
			return nil, err
		}
		platform := fmt.Sprintf("%s/%s", m.Platform.OS, m.Platform.Architecture)

		plugin.Platforms[platform] = &Layer{
			Config:   cfg,
			Manifest: manifest,
		}
	}

	// Fetch tags.
	if err = repo.Tags(ctx, "", func(t []string) error {
		tags = append(tags, t...)
		return nil
	}); err != nil {
		return nil, err
	}
	plugin.Tags = tags

	return plugin, nil
}
