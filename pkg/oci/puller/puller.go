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
	"fmt"

	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/file"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"

	"github.com/falcosecurity/falcoctl/pkg/oci"
)

// Puller implements pull operations.
type Puller struct {
	Client *auth.Client
}

// NewPuller create a new puller that can be used for pull operations.
// The client must be ready to be used by the puller.
func NewPuller(client *auth.Client) *Puller {
	return &Puller{
		Client: client,
	}
}

// Pull an artifact from a remote registry.
// Ref format follows: REGISTRY/REPO[:TAG|@DIGEST]. Ex. localhost:5000/hello:latest.
func (p *Puller) Pull(ctx context.Context, artifactType oci.ArtifactType, ref, destDir, os, arch string) (*oci.RegistryResult, error) {
	fileStore := file.New(destDir)

	repo, err := remote.NewRepository(ref)
	if err != nil {
		return nil, fmt.Errorf("unable to create new repository with ref %s: %w", ref, err)
	}
	repo.Client = p.Client

	copyOpts := oras.CopyOptions{}
	if artifactType == oci.Plugin {
		plt := &v1.Platform{
			OS:           os,
			Architecture: arch,
		}
		copyOpts.WithTargetPlatform(plt)
	}

	desc, err := oras.Copy(ctx, repo, ref, fileStore, ref, copyOpts)

	if err != nil {
		return nil, fmt.Errorf("unable to pull artifact %s with tag %s from repo %s: %w",
			repo.Reference.Repository, repo.Reference.Reference, repo.Reference.Repository, err)
	}

	return &oci.RegistryResult{
		Digest: string(desc.Digest),
	}, nil
}
