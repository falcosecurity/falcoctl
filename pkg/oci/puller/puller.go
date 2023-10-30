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

package puller

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"runtime"

	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/file"
	"oras.land/oras-go/v2/registry/remote"

	"github.com/falcosecurity/falcoctl/pkg/oci"
	"github.com/falcosecurity/falcoctl/pkg/oci/repository"
	"github.com/falcosecurity/falcoctl/pkg/output"
)

// Puller implements pull operations.
type Puller struct {
	Client    remote.Client
	tracker   output.Tracker
	plainHTTP bool
}

// NewPuller create a new puller that can be used for pull operations.
// The client must be ready to be used by the puller.
func NewPuller(client remote.Client, plainHTTP bool, tracker output.Tracker) *Puller {
	return &Puller{
		Client:    client,
		tracker:   tracker,
		plainHTTP: plainHTTP,
	}
}

// Pull an artifact from a remote registry.
// Ref format follows: REGISTRY/REPO[:TAG|@DIGEST]. Ex. localhost:5000/hello:latest.
func (p *Puller) Pull(ctx context.Context, ref, destDir, os, arch string) (*oci.RegistryResult, error) {
	fileStore, err := file.New(destDir)
	if err != nil {
		return nil, err
	}

	repo, err := repository.NewRepository(ref,
		repository.WithClient(p.Client),
		repository.WithPlainHTTP(p.plainHTTP))
	if err != nil {
		return nil, err
	}

	// if no tag was specified, "latest" is used
	if repo.Reference.Reference == "" {
		ref += ":" + oci.DefaultTag
		repo.Reference.Reference = oci.DefaultTag
	}

	refDesc, _, err := repo.FetchReference(ctx, ref)
	if err != nil {
		return nil, err
	}

	copyOpts := oras.CopyOptions{}
	copyOpts.Concurrency = 1
	if refDesc.MediaType == v1.MediaTypeImageIndex {
		plt := &v1.Platform{
			OS:           os,
			Architecture: arch,
		}
		copyOpts.WithTargetPlatform(plt)
	}

	localTarget := oras.Target(fileStore)

	if p.tracker != nil {
		localTarget = p.tracker(localTarget)
	}
	desc, err := oras.Copy(ctx, repo, ref, localTarget, ref, copyOpts)

	if err != nil {
		return nil, fmt.Errorf("unable to pull artifact %s with tag %s from repo %s: %w",
			repo.Reference.Repository, repo.Reference.Reference, repo.Reference.Repository, err)
	}

	manifest, err := manifestFromDesc(ctx, localTarget, &desc)
	if err != nil {
		return nil, err
	}

	var artifactType oci.ArtifactType
	switch manifest.Layers[0].MediaType {
	case oci.FalcoPluginLayerMediaType:
		artifactType = oci.Plugin
	case oci.FalcoRulesfileLayerMediaType:
		artifactType = oci.Rulesfile
	default:
		return nil, fmt.Errorf("unknown media type: %q", manifest.Layers[0].MediaType)
	}

	filename := manifest.Layers[0].Annotations[v1.AnnotationTitle]

	return &oci.RegistryResult{
		RootDigest: string(refDesc.Digest),
		Digest:     string(desc.Digest),
		Type:       artifactType,
		Filename:   filename,
	}, nil
}

// Descriptor retrieves the descriptor of an artifact from a remote repository.
func (p *Puller) Descriptor(ctx context.Context, ref string) (*v1.Descriptor, error) {
	repo, err := repository.NewRepository(ref, repository.WithClient(p.Client), repository.WithPlainHTTP(p.plainHTTP))
	if err != nil {
		return nil, err
	}

	desc, _, err := repo.FetchReference(ctx, ref)
	if err != nil {
		return nil, err
	}
	return &desc, nil
}

func manifestFromDesc(ctx context.Context, target oras.Target, desc *v1.Descriptor) (*v1.Manifest, error) {
	var manifest v1.Manifest

	descReader, err := target.Fetch(ctx, *desc)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch descriptor with digest %q: %w", desc.Digest, err)
	}
	defer descReader.Close()

	descBytes, err := io.ReadAll(descReader)
	if err != nil {
		return nil, fmt.Errorf("unable to read bytes from descriptor: %w", err)
	}

	if err = json.Unmarshal(descBytes, &manifest); err != nil {
		return nil, fmt.Errorf("unable to unmarshal manifest: %w", err)
	}

	if len(manifest.Layers) < 1 {
		return nil, fmt.Errorf("no layers in manifest")
	}

	return &manifest, nil
}

// manifestFromRef retieves the manifest of an artifact, also taking care of resolving to it walking through indexes.
func (p *Puller) manifestFromRef(ctx context.Context, ref string) (*v1.Manifest, error) {
	repo, err := repository.NewRepository(ref, repository.WithClient(p.Client), repository.WithPlainHTTP(p.plainHTTP))
	if err != nil {
		return nil, err
	}

	desc, manifestReader, err := repo.FetchReference(ctx, ref)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch reference %q: %w", ref, err)
	}
	defer manifestReader.Close()

	// Resolve to actual manifest if an index is found.
	if desc.MediaType == v1.MediaTypeImageIndex {
		var index v1.Index
		indexReader := manifestReader
		defer indexReader.Close()

		indexBytes, err := io.ReadAll(indexReader)
		if err != nil {
			return nil, fmt.Errorf("unable to read manifest: %w", err)
		}
		if err = json.Unmarshal(indexBytes, &index); err != nil {
			return nil, fmt.Errorf("unable to unmarshal manifest: %w", err)
		}

		// todo: decide if goos or arch should be passed to this function
		found := false
		for _, manifest := range index.Manifests {
			if manifest.Platform.OS == runtime.GOOS &&
				manifest.Platform.Architecture == runtime.GOARCH {
				desc = manifest
				found = true
				break
			}
		}

		if !found {
			return nil, fmt.Errorf("unable to find a manifest matching the given platform: %s %s", runtime.GOOS, runtime.GOARCH)
		}

		manifestReader, err = repo.Fetch(ctx, desc)
		if err != nil {
			return nil, fmt.Errorf("unable to fetch manifest desc with digest %s: %w", desc.Digest.String(), err)
		}
	}

	var manifest v1.Manifest
	manifestBytes, err := io.ReadAll(manifestReader)
	if err != nil {
		return nil, fmt.Errorf("unable to read bytes from manifest reader for ref %q: %w", ref, err)
	}

	if err = json.Unmarshal(manifestBytes, &manifest); err != nil {
		return nil, fmt.Errorf("unable to unmarshal manifest: %w", err)
	}

	return &manifest, nil
}

// GetArtifactConfig fetches only the config layer from a given ref.
func (p *Puller) GetArtifactConfig(ctx context.Context, ref string) (*oci.ArtifactConfig, error) {
	configBytes, err := p.PullConfigLayer(ctx, ref)
	if err != nil {
		return nil, err
	}

	var artifactConfig oci.ArtifactConfig
	if err = json.Unmarshal(configBytes, &artifactConfig); err != nil {
		return nil, err
	}

	return &artifactConfig, nil
}

// PullConfigLayer fetches only the config layer from a given ref.
func (p *Puller) PullConfigLayer(ctx context.Context, ref string) ([]byte, error) {
	repo, err := repository.NewRepository(ref, repository.WithClient(p.Client), repository.WithPlainHTTP(p.plainHTTP))
	if err != nil {
		return nil, err
	}

	manifest, err := p.manifestFromRef(ctx, ref)
	if err != nil {
		return nil, err
	}

	configRef := manifest.Config.Digest.String()

	descriptor, err := repo.Blobs().Resolve(ctx, configRef)
	if err != nil {
		return nil, err
	}

	rc, err := repo.Fetch(ctx, descriptor)
	if err != nil {
		return nil, err
	}

	configBytes, err := io.ReadAll(rc)
	if err != nil {
		return nil, err
	}

	if err := rc.Close(); err != nil {
		return nil, err
	}

	return configBytes, nil
}

// CheckAllowedType does a preliminary check on the manifest to state whether we are allowed
// or not to download this type of artifact. If allowedTypes is empty, everything is allowed,
// else it is used to perform the check.
func (p *Puller) CheckAllowedType(ctx context.Context, ref string, allowedTypes []oci.ArtifactType) error {
	if len(allowedTypes) == 0 {
		return nil
	}

	manifest, err := p.manifestFromRef(ctx, ref)
	if err != nil {
		return err
	}

	if len(manifest.Layers) == 0 {
		return fmt.Errorf("malformed artifact, expected to find at least one layer for ref %q", ref)
	}

	for _, t := range allowedTypes {
		if manifest.Layers[0].MediaType == t.ToMediaType() {
			return nil
		}
	}

	return fmt.Errorf("cannot download artifact of type %q: type not permitted", oci.HumanReadableMediaType(manifest.Layers[0].MediaType))
}
