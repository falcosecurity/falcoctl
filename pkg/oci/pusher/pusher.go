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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/opencontainers/image-spec/specs-go"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	logger "github.com/sirupsen/logrus"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/file"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"

	"github.com/falcosecurity/falcoctl/pkg/oci"
)

const (
	// ConfigLayerName is the name of config layers.
	ConfigLayerName = "config"
	// ArtifactsIndexName is the name of the index containing all manifests.
	ArtifactsIndexName = "index"
)

var (
	// ErrNotFound it is wrapped in not found errors returned by the ORAS library.
	ErrNotFound = errNotFound()
)

func errNotFound() error { return errors.New("not found") }

// ProgressTracker type of the tracker that the pusher accepts. It implements the tracker logic.
type ProgressTracker func(target oras.Target) oras.Target

// Pusher implements push operations.
type Pusher struct {
	Client  *auth.Client
	tracker ProgressTracker
}

// NewPusher create a new pusher that can be used for push operations.
func NewPusher(client *auth.Client, tracker ProgressTracker) *Pusher {
	return &Pusher{
		Client:  client,
		tracker: tracker,
	}
}

// Push an artifact to a remote registry.
//
// artifactType can be either a rule or plugin.
// artifactPath path of the artifact blob on the disk.
// ref format follows: REGISTRY/REPO[:TAG|@DIGEST]. Ex. localhost:5000/hello:latest.
func (p *Pusher) Push(ctx context.Context, artifactType oci.ArtifactType,
	ref string, options ...Option) (*oci.RegistryResult, error) {
	var dataDesc, configDesc, rootDesc *v1.Descriptor
	var err error

	o := &opts{}
	if err := Options(options).apply(o); err != nil {
		return nil, err
	}

	// Create the object to interact with the remote repo.
	repo, err := remote.NewRepository(ref)
	if err != nil {
		return nil, err
	}
	repo.Client = p.Client

	// Using ":latest" by default if no tag was provided.
	if repo.Reference.Reference == "" {
		repo.Reference.Reference = oci.DefaultTag
	}

	// Set remoteTarget and its tracker.
	remoteTarget := oras.Target(repo)

	if p.tracker != nil {
		remoteTarget = p.tracker(repo)
	}

	defaultCopyOptions := oras.DefaultCopyGraphOptions
	defaultCopyOptions.Concurrency = 1

	// Initialize the file store for this artifact.
	tmpDir, err := os.MkdirTemp("", "falcoctl")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmpDir)

	manifestDescs := make([]*v1.Descriptor, len(o.Filepaths))
	var fileStore *file.Store
	for i, artifactPath := range o.Filepaths {
		fileStore = file.New(tmpDir)

		platform := ""
		if len(o.Platforms) > i {
			platform = o.Platforms[i]
		}

		// Prepare data layer.
		absolutePath, err := filepath.Abs(artifactPath)
		if err != nil {
			return nil, err
		}
		if dataDesc, err = p.storeMainLayer(ctx, fileStore, artifactType, absolutePath); err != nil {
			return nil, err
		}

		// Prepare configuration layer.
		if configDesc, err = p.storeConfigLayer(ctx, fileStore, artifactType, o.Dependencies); err != nil {
			return nil, err
		}

		// Now we can create manifest, using the Config descriptor and principal Layer descriptor.
		if manifestDescs[i], err = p.packManifest(ctx, fileStore, configDesc, dataDesc, platform); err != nil {
			return nil, err
		}

		if err = oras.CopyGraph(ctx, fileStore, remoteTarget, *manifestDescs[i], defaultCopyOptions); err != nil {
			return nil, err
		}
	}

	switch len(manifestDescs) {
	case 0:
		panic("should never happen")
	case 1:
		rootDesc = manifestDescs[0]
	default:
		// Assuming this filestore to be memory only (size of the index should be less than 4MiB)
		fileStore = file.New("")
		if rootDesc, err = p.storeArtifactsIndex(ctx, fileStore, manifestDescs); err != nil {
			return nil, err
		}
	}

	// If we have only one manifest descriptor, fileStore points to the first and only file.Store we created.
	// Otherwise, it points to the filestore containing the
	rootReader, err := fileStore.Fetch(ctx, *rootDesc)
	if err != nil {
		return nil, err
	}
	defer rootReader.Close()

	// Tag the root descriptor remotely.
	err = repo.PushReference(ctx, *rootDesc, rootReader, repo.Reference.Reference)
	if err != nil {
		return nil, err
	}
	if len(o.Tags) > 0 {
		if err = oras.TagN(ctx, remoteTarget, repo.Reference.Reference, o.Tags, oras.DefaultTagNOptions); err != nil {
			return nil, err
		}
	}

	return &oci.RegistryResult{
		Digest: string(rootDesc.Digest),
	}, nil
}

func (p *Pusher) storeMainLayer(ctx context.Context, fileStore *file.Store,
	artifactType oci.ArtifactType, artifactPath string) (*v1.Descriptor, error) {
	var layerMediaType string

	switch artifactType {
	case oci.Rulesfile:
		layerMediaType = oci.FalcoRulesfileLayerMediaType
	case oci.Plugin:
		layerMediaType = oci.FalcoPluginLayerMediaType
	}

	// Add the content of the principal layer to the file store.
	desc, err := fileStore.Add(ctx, filepath.Base(artifactPath), layerMediaType, filepath.Clean(artifactPath))
	if err != nil {
		return nil, fmt.Errorf("unable to store artifact %s of type %s: %w", artifactPath, artifactType, err)
	}

	return &desc, nil
}

func (p *Pusher) storeConfigLayer(ctx context.Context, fileStore *file.Store,
	artifactType oci.ArtifactType, dependencies []string) (*v1.Descriptor, error) {
	var layerMediaType string
	// Create config and fill common fields of the config (empty for now).
	artifactConfig := oci.ArtifactConfig{}

	err := artifactConfig.ParseDependencies(dependencies...)
	if err != nil {
		return nil, err
	}

	switch artifactType {
	case oci.Rulesfile:
		layerMediaType = oci.FalcoRulesfileConfigMediaType
	case oci.Plugin:
		layerMediaType = oci.FalcoPluginConfigMediaType
	}

	return p.toFileStore(ctx, fileStore, layerMediaType, ConfigLayerName, artifactConfig)
}

func (p *Pusher) storeArtifactsIndex(ctx context.Context, fileStore *file.Store, manifestDescs []*v1.Descriptor) (*v1.Descriptor, error) {
	// fat manifest
	index := &v1.Index{
		Versioned: specs.Versioned{SchemaVersion: 2},
		MediaType: v1.MediaTypeImageIndex,
	}

	// copy manifests
	for _, manifestDesc := range manifestDescs {
		index.Manifests = append(index.Manifests, *manifestDesc)
	}

	return p.toFileStore(ctx, fileStore, index.MediaType, ArtifactsIndexName, index)
}

func (p *Pusher) toFileStore(ctx context.Context, fileStore *file.Store, mediaType, name string, data interface{}) (*v1.Descriptor, error) {
	dataBytes, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal data of media type %q: %w", mediaType, err)
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

	if _, err := configFile.Write(dataBytes); err != nil {
		return nil, fmt.Errorf("unable to write data of media type %q to temporary file %s: %w", mediaType, configFile.Name(), err)
	}

	desc, err := fileStore.Add(ctx, name, mediaType, filepath.Clean(configFile.Name()))
	if err != nil {
		return nil, fmt.Errorf("unable to store data of media type %q in the file store: %w", mediaType, err)
	}
	return &desc, nil
}

func (p *Pusher) packManifest(ctx context.Context, fileStore *file.Store,
	configDesc, dataDesc *v1.Descriptor, platform string) (*v1.Descriptor, error) {
	// Now we can create manifest, using the Config descriptor and principal Layer descriptor.
	packOptions := oras.PackOptions{ConfigDescriptor: configDesc}
	desc, err := oras.Pack(ctx, fileStore, []v1.Descriptor{*dataDesc}, packOptions)
	if err != nil {
		return nil, fmt.Errorf("unable to generate manifest for config layer %s and data layer %s: %w", configDesc.MediaType, dataDesc.MediaType, err)
	}

	if dataDesc.MediaType == oci.FalcoPluginLayerMediaType {
		tokens := strings.Split(platform, "/")
		desc.Platform = &v1.Platform{
			OS:           tokens[0],
			Architecture: tokens[1],
		}
	}

	return &desc, nil
}
