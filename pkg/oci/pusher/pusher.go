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

package pusher

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	logger "github.com/sirupsen/logrus"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/file"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"

	"github.com/falcosecurity/falcoctl/pkg/oci"
)

// Pusher implements push operations.
type Pusher struct {
	Client    *auth.Client
	fileStore *file.Store
}

// NewPusher create a new pusher that can be used for push operations.
func NewPusher(ctx context.Context, client *auth.Client) (*Pusher, error) {
	return &Pusher{
		Client:    client,
		fileStore: file.New(""),
	}, nil
}

// Push an artifact to a remote registry.
// artifactType can be either a rule or plugin.
// artifactPath path of the artifact blob on the disk.
// ref format follows: REGISTRY/REPO[:TAG|@DIGEST]. Ex. localhost:5000/hello:latest.
// dependencies rule to plugin dependency expressed as pluginName:version. Ex. cloudtrail:1.2.3.
func (p *Pusher) Push(ctx context.Context, artifactType oci.ArtifactType,
	artifactPath, ref string, dependencies ...string) (*oci.RegistryResult, error) {
	var dataDesc, configDesc, manifestDesc *v1.Descriptor
	var err error

	// Prepare data layer.
	if dataDesc, err = p.storeMainLayer(ctx, artifactType, artifactPath); err != nil {
		return nil, err
	}

	// Prepare configuration layer.
	if configDesc, err = p.storeConfigLayer(ctx, artifactType, dependencies); err != nil {
		return nil, err
	}

	// Now we can create manifest, using the Config descriptor and principal Layer descriptor.
	if manifestDesc, err = p.packManifest(ctx, configDesc, dataDesc); err != nil {
		return nil, err
	}

	// Prepare real push operation using the authenticated client.
	repo, err := remote.NewRepository(ref)
	if err != nil {
		return nil, err
	}
	repo.Client = p.Client

	// Tag the manifest desc locally.
	if err = p.fileStore.Tag(ctx, *manifestDesc, repo.Reference.Reference); err != nil {
		return nil, err
	}

	_, err = oras.Copy(ctx, p.fileStore, repo.Reference.Reference, repo, "", oras.DefaultCopyOptions)
	if err != nil {
		return nil, err
	}

	// Todo(loresuso, alacuku): not sure what to return. The manifest itself could be enough since it holds useful data.
	return &oci.RegistryResult{
		Digest: string(manifestDesc.Digest),
	}, nil
}

func (p *Pusher) storeMainLayer(ctx context.Context, artifactType oci.ArtifactType, artifactPath string) (*v1.Descriptor, error) {
	var layerMediaType string

	switch artifactType {
	case oci.Rule:
		layerMediaType = oci.FalcoRuleLayerMediaType
	case oci.Plugin:
		layerMediaType = oci.FalcoPluginLayerMediaType
	}

	// Add the content of the principal layer to the file store.
	desc, err := p.fileStore.Add(ctx, filepath.Clean(artifactPath), layerMediaType, artifactPath)
	if err != nil {
		return nil, fmt.Errorf("unable to store artifact %s of type %s: %w", artifactPath, artifactType, err)
	}

	return &desc, nil
}

func (p *Pusher) storeConfigLayer(ctx context.Context, artifactType oci.ArtifactType, dependencies []string) (*v1.Descriptor, error) {
	var layerMediaType string
	// Create config and fill common fields of the config (empty for now).
	artifactConfig := oci.ArtifactConfig{}

	switch artifactType {
	case oci.Rule:
		layerMediaType = oci.FalcoRuleConfigMediaType
		if err := artifactConfig.SetRequiredPluginVersions(dependencies...); err != nil {
			return nil, fmt.Errorf("unable to set dependencies %s: %w", dependencies, err)
		}
	case oci.Plugin:
		layerMediaType = oci.FalcoPluginConfigMediaType
	}

	configData, err := json.Marshal(artifactConfig)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal artifact config %v: %w", artifactConfig, err)
	}

	// Create temporary common file. This is needed because we have to add it to the store.
	configFile, err := os.CreateTemp("", "falcoctl")
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := configFile.Close(); err != nil {
			logger.Printf("Error closing file: %s\n", err)
		}
	}()

	if _, err := configFile.Write(configData); err != nil {
		return nil, fmt.Errorf("unable to write config file to temporary file %s: %w", configFile.Name(), err)
	}

	desc, err := p.fileStore.Add(ctx, "config", layerMediaType, filepath.Clean(configFile.Name()))
	if err != nil {
		return nil, fmt.Errorf("unable to store artifact %s of type %s: %w", configFile.Name(), artifactType, err)
	}

	return &desc, nil
}

func (p *Pusher) packManifest(ctx context.Context, configDesc, dataDesc *v1.Descriptor) (*v1.Descriptor, error) {
	// Now we can create manifest, using the Config descriptor and principal Layer descriptor.
	packOptions := oras.PackOptions{ConfigDescriptor: configDesc}
	desc, err := oras.Pack(ctx, p.fileStore, []v1.Descriptor{*dataDesc}, packOptions)
	if err != nil {
		return nil, fmt.Errorf("unable to generate manifest for config layer %s and data layer %s: %w", configDesc.MediaType, dataDesc.MediaType, err)
	}

	return &desc, nil
}
