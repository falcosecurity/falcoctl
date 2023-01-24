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
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/file"
	"oras.land/oras-go/v2/registry/remote"

	"github.com/falcosecurity/falcoctl/pkg/oci"
	"github.com/falcosecurity/falcoctl/pkg/oci/repository"
	"github.com/falcosecurity/falcoctl/pkg/output"
)

const (
	// ConfigLayerName is the name of config layers.
	ConfigLayerName = "config"
	// ArtifactsIndexName is the name of the index containing all manifests.
	ArtifactsIndexName = "index"
)

var (
	// ErrInvalidPlatformFormat error when the platform is invalid.
	ErrInvalidPlatformFormat = errors.New("invalid platform format")
	// ErrMismatchFilepathAndPlatform error when the number of filepaths and platforms is not the same.
	ErrMismatchFilepathAndPlatform = errors.New("number of filepaths and platform should be the same")
	// ErrInvalidNumberRulesfiles error when the number of rulesfiles is not the one expected.
	ErrInvalidNumberRulesfiles = errors.New("invalid number of rulesfiles")
	// ErrInvalidDependenciesFormat error when the dependencies are invalid.
	ErrInvalidDependenciesFormat = errors.New("invalid dependency format")
)

// Pusher implements push operations.
type Pusher struct {
	Client    remote.Client
	tracker   output.Tracker
	plainHTTP bool
	// workingDir is an internal temporary directory that the Pusher
	// uses to create temporary files to add them to the filestore and push them.
	workingDir string
}

// NewPusher create a new pusher that can be used for push operations.
func NewPusher(client remote.Client, plainHTTP bool, tracker output.Tracker) *Pusher {
	return &Pusher{
		Client:    client,
		tracker:   tracker,
		plainHTTP: plainHTTP,
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

	// First thing check that we do not have multiple rulesfiles.
	if artifactType == oci.Rulesfile && len(o.Filepaths) != 1 {
		return nil, fmt.Errorf("expecting 1 rulesfile object received %d: %w", len(o.Filepaths), ErrInvalidNumberRulesfiles)
	}

	repo, err := repository.NewRepository(ref,
		repository.WithClient(p.Client),
		repository.WithPlainHTTP(p.plainHTTP))
	if err != nil {
		return nil, err
	}

	tags := o.Tags

	// Using ":latest" by default if no tag was provided.
	if repo.Reference.Reference == "" {
		if len(tags) > 0 {
			repo.Reference.Reference, tags = tags[0], tags[1:]
		} else {
			repo.Reference.Reference = oci.DefaultTag
		}
	}

	// Set remoteTarget and its tracker.
	remoteTarget := oras.Target(repo)

	if p.tracker != nil {
		remoteTarget = p.tracker(repo)
	}

	defaultCopyOptions := oras.DefaultCopyGraphOptions
	defaultCopyOptions.Concurrency = 1

	// Initialize the file store for this artifact.
	p.workingDir, err = os.MkdirTemp("", "falcoctl")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(p.workingDir)

	manifestDescs := make([]*v1.Descriptor, len(o.Filepaths))
	var fileStore *file.Store
	for i, artifactPath := range o.Filepaths {
		fileStore = file.New(p.workingDir)

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
		if configDesc, err = p.storeConfigLayer(ctx, fileStore, artifactType, o.ArtifactConfig); err != nil {
			return nil, err
		}

		// Now we can create manifest, using the Config descriptor and principal Layer descriptor.
		if manifestDescs[i], err = p.packManifest(ctx, fileStore, configDesc,
			dataDesc, platform, o.AnnotationSource); err != nil {
			return nil, err
		}

		if err = oras.CopyGraph(ctx, fileStore, remoteTarget, *manifestDescs[i], defaultCopyOptions); err != nil {
			return nil, err
		}
	}

	if artifactType == oci.Rulesfile {
		// We should have only one manifestDesc.
		rootDesc = manifestDescs[0]
	} else {
		// Here we are in the case when we are dealing with a plugin.
		// Assuming this filestore to be memory only (size of the index should be less than 4MiB)
		fileStore = file.New("")
		if rootDesc, err = p.storeArtifactsIndex(ctx, fileStore, manifestDescs, o.AnnotationSource); err != nil {
			return nil, err
		}
	}

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

	if len(tags) > 0 {
		tagNOptions := oras.DefaultTagNOptions
		tagNOptions.Concurrency = 1
		if err = oras.TagN(ctx, remoteTarget, repo.Reference.Reference, o.Tags, tagNOptions); err != nil {
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
	artifactType oci.ArtifactType, artifactConfig *oci.ArtifactConfig) (*v1.Descriptor, error) {
	var layerMediaType string
	switch artifactType {
	case oci.Rulesfile:
		layerMediaType = oci.FalcoRulesfileConfigMediaType
	case oci.Plugin:
		layerMediaType = oci.FalcoPluginConfigMediaType
	}

	// todo: this is likely unnecessary, since the json marshaller should do that. double-check
	if artifactConfig == nil {
		artifactConfig = &oci.ArtifactConfig{}
	}

	return p.toFileStore(ctx, fileStore, layerMediaType, ConfigLayerName, artifactConfig)
}

func (p *Pusher) storeArtifactsIndex(ctx context.Context, fileStore *file.Store,
	manifestDescs []*v1.Descriptor, annotationSource string) (*v1.Descriptor, error) {
	// fat manifest
	index := &v1.Index{
		Versioned: specs.Versioned{SchemaVersion: 2},
		MediaType: v1.MediaTypeImageIndex,
	}

	if annotationSource != "" {
		index.Annotations = make(map[string]string)
		index.Annotations[v1.AnnotationSource] = annotationSource
	}

	// copy manifests
	for _, manifestDesc := range manifestDescs {
		index.Manifests = append(index.Manifests, *manifestDesc)
	}

	return p.toFileStore(ctx, fileStore, index.MediaType, ArtifactsIndexName, index)
}

func (p *Pusher) toFileStore(ctx context.Context, fileStore *file.Store, mediaType, name string, data interface{}) (desc *v1.Descriptor, err error) {
	dataBytes, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal data of media type %q: %w", mediaType, err)
	}

	// Create temporary common file. This is needed because we have to add it to the store.
	configFile, err := os.CreateTemp(p.workingDir, "falcoctl")
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			return
		}
		err = configFile.Close()
	}()

	if _, err := configFile.Write(dataBytes); err != nil {
		return nil, fmt.Errorf("unable to write data of media type %q to temporary file %s: %w", mediaType, configFile.Name(), err)
	}

	d, err := fileStore.Add(ctx, name, mediaType, filepath.Clean(configFile.Name()))
	if err != nil {
		return nil, fmt.Errorf("unable to store data of media type %q in the file store: %w", mediaType, err)
	}
	desc = &d
	return
}

func (p *Pusher) packManifest(ctx context.Context, fileStore *file.Store,
	configDesc, dataDesc *v1.Descriptor, platform, annotationSource string) (*v1.Descriptor, error) {
	// Now we can create manifest, using the Config descriptor and principal Layer descriptor.
	// In case annotation source is passed, we put it in the ManifestAnnotations.
	var packOptions oras.PackOptions
	if annotationSource != "" {
		annotations := make(map[string]string)
		annotations[v1.AnnotationSource] = annotationSource
		packOptions = oras.PackOptions{ConfigDescriptor: configDesc, ManifestAnnotations: annotations}
	} else {
		packOptions = oras.PackOptions{ConfigDescriptor: configDesc}
	}

	desc, err := oras.Pack(ctx, fileStore, []v1.Descriptor{*dataDesc}, packOptions)
	if err != nil {
		return nil, fmt.Errorf("unable to generate manifest for config layer %s and data layer %s: %w", configDesc.MediaType, dataDesc.MediaType, err)
	}

	if dataDesc.MediaType == oci.FalcoPluginLayerMediaType {
		tokens := strings.Split(platform, "/")
		if len(tokens) != 2 {
			return nil, fmt.Errorf("platform %q: %w", platform, ErrInvalidPlatformFormat)
		}
		desc.Platform = &v1.Platform{
			OS:           tokens[0],
			Architecture: tokens[1],
		}
	}

	return &desc, nil
}
