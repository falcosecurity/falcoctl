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

package puller

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/file"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"

	"github.com/falcosecurity/falcoctl/pkg/oci"
)

// ProgressTracker type of the tracker that the puller accepts. It implements the tracker logic.
type ProgressTracker func(target oras.Target) oras.Target

// Puller implements pull operations.
type Puller struct {
	Client  *auth.Client
	tracker ProgressTracker
}

// NewPuller create a new puller that can be used for pull operations.
// The client must be ready to be used by the puller.
func NewPuller(client *auth.Client, tracker ProgressTracker) *Puller {
	return &Puller{
		Client:  client,
		tracker: tracker,
	}
}

// Pull an artifact from a remote registry.
// Ref format follows: REGISTRY/REPO[:TAG|@DIGEST]. Ex. localhost:5000/hello:latest.
func (p *Puller) Pull(ctx context.Context, ref, destDir, os, arch string) (*oci.RegistryResult, error) {
	fileStore := file.New(destDir)

	repo, err := remote.NewRepository(ref)
	if err != nil {
		return nil, fmt.Errorf("unable to create new repository with ref %s: %w", ref, err)
	}
	repo.Client = p.Client

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

	descReader, err := localTarget.Fetch(ctx, desc)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch descriptor with digest %q: %w", desc.Digest, err)
	}
	defer descReader.Close()

	var manifest v1.Manifest
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

	var artifactType oci.ArtifactType
	switch manifest.Layers[0].MediaType {
	case oci.FalcoPluginLayerMediaType:
		artifactType = oci.Plugin
	case oci.FalcoRulesfileLayerMediaType:
		artifactType = oci.Rulesfile
	default:
		return nil, fmt.Errorf("unknown media type: %q", manifest.Layers[0].MediaType)
	}

	return &oci.RegistryResult{
		Digest: string(desc.Digest),
		Type:   artifactType,
	}, nil
}
