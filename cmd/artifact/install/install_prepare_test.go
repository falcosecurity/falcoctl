// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The Falco Authors
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

package install

import (
	"context"
	"fmt"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcoctl/pkg/index/cache"
	"github.com/falcosecurity/falcoctl/pkg/index/index"
	"github.com/falcosecurity/falcoctl/pkg/oci"
	"github.com/falcosecurity/falcoctl/pkg/options"
)

type fakeConfigProvider struct {
	configs map[string]*oci.ArtifactConfig
}

func (f *fakeConfigProvider) ArtifactConfig(_ context.Context, ref, _, _ string) (*oci.ArtifactConfig, error) {
	cfg, ok := f.configs[ref]
	if !ok {
		return nil, fmt.Errorf("config not found for ref %q", ref)
	}
	return cfg, nil
}

func newTestIndexCache(entries ...*index.Entry) *cache.Cache {
	idx := index.New("test")
	for _, e := range entries {
		idx.Upsert(e)
	}

	merged := index.NewMergedIndexes()
	merged.Merge(idx)

	return &cache.Cache{MergedIndexes: merged}
}

func newTestInstallOptions(t *testing.T, indexCache *cache.Cache, resolveDeps bool) *artifactInstallOptions {
	t.Helper()

	common := options.NewOptions()
	common.Initialize(options.WithWriter(io.Discard), options.WithIndexCache(indexCache))

	return &artifactInstallOptions{
		Common:       common,
		platformOS:   "linux",
		platformArch: "amd64",
		resolveDeps:  resolveDeps,
	}
}

func TestPrepareArtifactList_NoDeps_KeepsHighestVersion(t *testing.T) {
	idxCache := newTestIndexCache(
		&index.Entry{Name: "foo", Registry: "ghcr.io", Repository: "acme/foo"},
	)

	o := newTestInstallOptions(t, idxCache, false)

	ctx := context.Background()

	foo100 := "ghcr.io/acme/foo:1.0.0"
	foo200 := "ghcr.io/acme/foo:2.0.0"
	foo150 := "ghcr.io/acme/foo:1.5.0"

	provider := &fakeConfigProvider{configs: map[string]*oci.ArtifactConfig{
		foo100: {Name: "foo", Version: "1.0.0"},
		foo200: {Name: "foo", Version: "2.0.0"},
		foo150: {Name: "foo", Version: "1.5.0"},
	}}

	artifacts, err := o.prepareArtifactList(ctx, provider.ArtifactConfig, []string{
		"foo:1.0.0",
		"foo:2.0.0",
		"foo:1.5.0",
	})
	assert.Len(t, artifacts, 1, "should keep only one version")
	require.NoError(t, err)

	refs := make([]string, 0, len(artifacts))
	for _, info := range artifacts {
		refs = append(refs, info.ref)
	}

	assert.Equal(t, []string{foo200}, refs, "should keep highest version 2.0.0")
}

func TestPrepareArtifactList_NoDeps_UnknownRefReturnsError(t *testing.T) {
	idxCache := newTestIndexCache(
		&index.Entry{Name: "foo", Registry: "ghcr.io", Repository: "acme/foo"},
	)

	o := newTestInstallOptions(t, idxCache, false)

	ctx := context.Background()
	artifacts, err := o.prepareArtifactList(ctx, nil, []string{"does-not-exist"})
	require.Error(t, err)
	assert.Nil(t, artifacts)
}

func TestPrepareArtifactList_WithDeps_ExpandsSingleDependency(t *testing.T) {
	idxCache := newTestIndexCache(
		&index.Entry{Name: "falco-rules", Registry: "ghcr.io", Repository: "falcosecurity/falco-rules"},
		&index.Entry{Name: "json-plugin", Registry: "ghcr.io", Repository: "falcosecurity/plugins/json"},
	)

	o := newTestInstallOptions(t, idxCache, true)

	ctx := context.Background()
	rulesRef, err := idxCache.ResolveReference("falco-rules:1.0.0")
	require.NoError(t, err)
	jsonRef, err := idxCache.ResolveReference("json-plugin:1.0.0")
	require.NoError(t, err)

	provider := &fakeConfigProvider{configs: map[string]*oci.ArtifactConfig{
		rulesRef: {
			Name:    "falco-rules",
			Version: "1.0.0",
			Dependencies: []oci.ArtifactDependency{{
				Name:    "json-plugin",
				Version: "1.0.0",
			}},
		},
		jsonRef: {
			Name:    "json-plugin",
			Version: "1.0.0",
		},
	}}

	artifacts, err := o.prepareArtifactList(ctx, provider.ArtifactConfig, []string{"falco-rules:1.0.0"})
	require.NoError(t, err)

	assert.Len(t, artifacts, 2)

	refs := make([]string, 0, len(artifacts))
	for _, info := range artifacts {
		refs = append(refs, info.ref)
	}

	assert.ElementsMatch(t, []string{rulesRef, jsonRef}, refs)
}

func TestPrepareArtifactList_WithDeps_TransitiveDependencies(t *testing.T) {
	// k8saudit-rules -> cloudtrail-plugin -> json-plugin
	idxCache := newTestIndexCache(
		&index.Entry{Name: "k8saudit-rules", Registry: "ghcr.io", Repository: "falcosecurity/rules/k8saudit"},
		&index.Entry{Name: "cloudtrail-plugin", Registry: "ghcr.io", Repository: "falcosecurity/plugins/cloudtrail"},
		&index.Entry{Name: "json-plugin", Registry: "ghcr.io", Repository: "falcosecurity/plugins/json"},
	)

	o := newTestInstallOptions(t, idxCache, true)

	ctx := context.Background()
	k8sRef, err := idxCache.ResolveReference("k8saudit-rules:2.0.0")
	require.NoError(t, err)
	cloudtrailRef, err := idxCache.ResolveReference("cloudtrail-plugin:0.8.0")
	require.NoError(t, err)
	jsonRef, err := idxCache.ResolveReference("json-plugin:0.5.0")
	require.NoError(t, err)

	provider := &fakeConfigProvider{configs: map[string]*oci.ArtifactConfig{
		k8sRef: {
			Name:    "k8saudit-rules",
			Version: "2.0.0",
			Dependencies: []oci.ArtifactDependency{{
				Name:    "cloudtrail-plugin",
				Version: "0.8.0",
			}},
		},
		cloudtrailRef: {
			Name:    "cloudtrail-plugin",
			Version: "0.8.0",
			Dependencies: []oci.ArtifactDependency{{
				Name:    "json-plugin",
				Version: "0.5.0",
			}},
		},
		jsonRef: {
			Name:    "json-plugin",
			Version: "0.5.0",
		},
	}}

	artifacts, err := o.prepareArtifactList(ctx, provider.ArtifactConfig, []string{"k8saudit-rules:2.0.0"})
	require.NoError(t, err)
	assert.Len(t, artifacts, 3, "should resolve all transitive dependencies")

	refs := make([]string, 0, len(artifacts))
	for _, info := range artifacts {
		refs = append(refs, info.ref)
	}

	assert.ElementsMatch(t, []string{k8sRef, cloudtrailRef, jsonRef}, refs)
}

func TestPrepareArtifactList_WithDeps_SharedDependency(t *testing.T) {
	// Both k8saudit-rules and cloudtrail-rules depend on json-plugin
	idxCache := newTestIndexCache(
		&index.Entry{Name: "k8saudit-rules", Registry: "ghcr.io", Repository: "falcosecurity/rules/k8saudit"},
		&index.Entry{Name: "cloudtrail-rules", Registry: "ghcr.io", Repository: "falcosecurity/rules/cloudtrail"},
		&index.Entry{Name: "json-plugin", Registry: "ghcr.io", Repository: "falcosecurity/plugins/json"},
	)

	o := newTestInstallOptions(t, idxCache, true)

	ctx := context.Background()
	k8sRef, err := idxCache.ResolveReference("k8saudit-rules:1.0.0")
	require.NoError(t, err)
	cloudtrailRef, err := idxCache.ResolveReference("cloudtrail-rules:1.0.0")
	require.NoError(t, err)
	jsonRef, err := idxCache.ResolveReference("json-plugin:0.5.0")
	require.NoError(t, err)

	provider := &fakeConfigProvider{configs: map[string]*oci.ArtifactConfig{
		k8sRef: {
			Name:    "k8saudit-rules",
			Version: "1.0.0",
			Dependencies: []oci.ArtifactDependency{{
				Name:    "json-plugin",
				Version: "0.5.0",
			}},
		},
		cloudtrailRef: {
			Name:    "cloudtrail-rules",
			Version: "1.0.0",
			Dependencies: []oci.ArtifactDependency{{
				Name:    "json-plugin",
				Version: "0.5.0",
			}},
		},
		jsonRef: {
			Name:    "json-plugin",
			Version: "0.5.0",
		},
	}}

	artifacts, err := o.prepareArtifactList(ctx, provider.ArtifactConfig, []string{"k8saudit-rules:1.0.0", "cloudtrail-rules:1.0.0"})
	require.NoError(t, err)
	assert.Len(t, artifacts, 3, "shared dependency json-plugin should only appear once")

	refs := make([]string, 0, len(artifacts))
	for _, info := range artifacts {
		refs = append(refs, info.ref)
	}

	assert.ElementsMatch(t, []string{k8sRef, cloudtrailRef, jsonRef}, refs)
}

func TestPrepareArtifactList_WithDeps_BumpsVersionWhenHigherRequired(t *testing.T) {
	// k8saudit-rules requires json-plugin:0.7.0, cloudtrail-rules requires json-plugin:0.5.0
	// Should use the higher version 0.7.0
	idxCache := newTestIndexCache(
		&index.Entry{Name: "k8saudit-rules", Registry: "ghcr.io", Repository: "falcosecurity/rules/k8saudit"},
		&index.Entry{Name: "cloudtrail-rules", Registry: "ghcr.io", Repository: "falcosecurity/rules/cloudtrail"},
		&index.Entry{Name: "json-plugin", Registry: "ghcr.io", Repository: "falcosecurity/plugins/json"},
	)

	o := newTestInstallOptions(t, idxCache, true)

	ctx := context.Background()
	k8sRef, err := idxCache.ResolveReference("k8saudit-rules:1.0.0")
	require.NoError(t, err)
	cloudtrailRef, err := idxCache.ResolveReference("cloudtrail-rules:1.0.0")
	require.NoError(t, err)
	jsonRef050, err := idxCache.ResolveReference("json-plugin:0.5.0")
	require.NoError(t, err)
	jsonRef070, err := idxCache.ResolveReference("json-plugin:0.7.0")
	require.NoError(t, err)

	provider := &fakeConfigProvider{configs: map[string]*oci.ArtifactConfig{
		k8sRef: {
			Name:    "k8saudit-rules",
			Version: "1.0.0",
			Dependencies: []oci.ArtifactDependency{{
				Name:    "json-plugin",
				Version: "0.7.0",
			}},
		},
		cloudtrailRef: {
			Name:    "cloudtrail-rules",
			Version: "1.0.0",
			Dependencies: []oci.ArtifactDependency{{
				Name:    "json-plugin",
				Version: "0.5.0",
			}},
		},
		jsonRef050: {
			Name:    "json-plugin",
			Version: "0.5.0",
		},
		jsonRef070: {
			Name:    "json-plugin",
			Version: "0.7.0",
		},
	}}

	artifacts, err := o.prepareArtifactList(ctx, provider.ArtifactConfig, []string{"cloudtrail-rules:1.0.0", "k8saudit-rules:1.0.0"})
	require.NoError(t, err)
	assert.Len(t, artifacts, 3)

	refs := make([]string, 0, len(artifacts))
	for _, info := range artifacts {
		refs = append(refs, info.ref)
	}

	assert.ElementsMatch(t, []string{k8sRef, cloudtrailRef, jsonRef070}, refs,
		"should use higher version 0.7.0 of json-plugin, not 0.5.0")
}

func TestPrepareArtifactList_WithDeps_IncompatibleMajorVersionsError(t *testing.T) {
	// k8saudit-rules requires json-plugin:2.0.0, cloudtrail-rules requires json-plugin:1.0.0
	// Major version mismatch should error
	idxCache := newTestIndexCache(
		&index.Entry{Name: "k8saudit-rules", Registry: "ghcr.io", Repository: "falcosecurity/rules/k8saudit"},
		&index.Entry{Name: "cloudtrail-rules", Registry: "ghcr.io", Repository: "falcosecurity/rules/cloudtrail"},
		&index.Entry{Name: "json-plugin", Registry: "ghcr.io", Repository: "falcosecurity/plugins/json"},
	)

	o := newTestInstallOptions(t, idxCache, true)

	ctx := context.Background()
	k8sRef, err := idxCache.ResolveReference("k8saudit-rules:1.0.0")
	require.NoError(t, err)
	cloudtrailRef, err := idxCache.ResolveReference("cloudtrail-rules:1.0.0")
	require.NoError(t, err)
	jsonRef100, err := idxCache.ResolveReference("json-plugin:1.0.0")
	require.NoError(t, err)
	jsonRef200, err := idxCache.ResolveReference("json-plugin:2.0.0")
	require.NoError(t, err)

	provider := &fakeConfigProvider{configs: map[string]*oci.ArtifactConfig{
		k8sRef: {
			Name:    "k8saudit-rules",
			Version: "1.0.0",
			Dependencies: []oci.ArtifactDependency{{
				Name:    "json-plugin",
				Version: "2.0.0",
			}},
		},
		cloudtrailRef: {
			Name:    "cloudtrail-rules",
			Version: "1.0.0",
			Dependencies: []oci.ArtifactDependency{{
				Name:    "json-plugin",
				Version: "1.0.0",
			}},
		},
		jsonRef100: {
			Name:    "json-plugin",
			Version: "1.0.0",
		},
		jsonRef200: {
			Name:    "json-plugin",
			Version: "2.0.0",
		},
	}}

	artifacts, err := o.prepareArtifactList(ctx, provider.ArtifactConfig, []string{"k8saudit-rules:1.0.0", "cloudtrail-rules:1.0.0"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot satisfy dependencies")
	assert.Nil(t, artifacts)
}

func TestPrepareArtifactList_WithDeps_AlternativeDependency(t *testing.T) {
	// falco-rules requires json-plugin:1.0.0 OR yaml-plugin:1.0.0
	// User provides yaml-plugin, should use that alternative
	idxCache := newTestIndexCache(
		&index.Entry{Name: "falco-rules", Registry: "ghcr.io", Repository: "falcosecurity/falco-rules"},
		&index.Entry{Name: "json-plugin", Registry: "ghcr.io", Repository: "falcosecurity/plugins/json"},
		&index.Entry{Name: "yaml-plugin", Registry: "ghcr.io", Repository: "falcosecurity/plugins/yaml"},
	)

	o := newTestInstallOptions(t, idxCache, true)

	ctx := context.Background()
	rulesRef, err := idxCache.ResolveReference("falco-rules:1.0.0")
	require.NoError(t, err)
	yamlRef, err := idxCache.ResolveReference("yaml-plugin:1.0.0")
	require.NoError(t, err)
	jsonRef, err := idxCache.ResolveReference("json-plugin:1.0.0")
	require.NoError(t, err)

	provider := &fakeConfigProvider{configs: map[string]*oci.ArtifactConfig{
		rulesRef: {
			Name:    "falco-rules",
			Version: "1.0.0",
			Dependencies: []oci.ArtifactDependency{{
				Name:    "json-plugin",
				Version: "1.0.0",
				Alternatives: []oci.Dependency{
					{Name: "yaml-plugin", Version: "1.0.0"},
				},
			}},
		},
		yamlRef: {
			Name:    "yaml-plugin",
			Version: "1.0.0",
		},
		jsonRef: {
			Name:    "json-plugin",
			Version: "1.0.0",
		},
	}}

	// User explicitly installs yaml-plugin, so it should be used as alternative
	artifacts, err := o.prepareArtifactList(ctx, provider.ArtifactConfig, []string{"falco-rules:1.0.0", "yaml-plugin:1.0.0"})
	require.NoError(t, err)
	assert.Len(t, artifacts, 2, "should not install json-plugin since yaml-plugin alternative is present")

	refs := make([]string, 0, len(artifacts))
	for _, info := range artifacts {
		refs = append(refs, info.ref)
	}

	assert.ElementsMatch(t, []string{rulesRef, yamlRef}, refs)
}

func TestPrepareArtifactList_WithDeps_AlternativeRequiresResolve(t *testing.T) {
	// This test ensures that when bumping an alternative dependency,
	// the resolver is called to convert "name:version" to full reference.
	// Without resolver call, upsertMap would receive "yaml-plugin:1.5.0"
	// instead of "ghcr.io/falcosecurity/plugins/yaml:1.5.0"
	idxCache := newTestIndexCache(
		&index.Entry{Name: "falco-rules", Registry: "ghcr.io", Repository: "falcosecurity/falco-rules"},
		&index.Entry{Name: "json-plugin", Registry: "ghcr.io", Repository: "falcosecurity/plugins/json"},
		&index.Entry{Name: "yaml-plugin", Registry: "ghcr.io", Repository: "falcosecurity/plugins/yaml"},
	)

	o := newTestInstallOptions(t, idxCache, true)

	ctx := context.Background()
	rulesRef, _ := idxCache.ResolveReference("falco-rules:1.0.0")
	yamlRef100, _ := idxCache.ResolveReference("yaml-plugin:1.0.0")
	yamlRef150, _ := idxCache.ResolveReference("yaml-plugin:1.5.0") // Must be resolved via index!

	// CRITICAL: configs are keyed by RESOLVED refs (with registry/repo)
	// If resolver is not called, upsertMap gets "yaml-plugin:1.5.0" and fails
	provider := &fakeConfigProvider{configs: map[string]*oci.ArtifactConfig{
		rulesRef: {
			Name:    "falco-rules",
			Version: "1.0.0",
			Dependencies: []oci.ArtifactDependency{{
				Name:    "json-plugin",
				Version: "2.0.0",
				Alternatives: []oci.Dependency{
					{Name: "yaml-plugin", Version: "1.5.0"}, // This needs resolver!
				},
			}},
		},
		yamlRef100: {
			Name:    "yaml-plugin",
			Version: "1.0.0",
		},
		// Only the RESOLVED ref has config - not the short name
		yamlRef150: {
			Name:    "yaml-plugin",
			Version: "1.5.0",
		},
	}}

	artifacts, err := o.prepareArtifactList(ctx, provider.ArtifactConfig, []string{"falco-rules:1.0.0", "yaml-plugin:1.0.0"})
	require.NoError(t, err, "should resolve alternative yaml-plugin:1.5.0 via index")
	assert.Len(t, artifacts, 2)

	refs := make([]string, 0, len(artifacts))
	for _, info := range artifacts {
		refs = append(refs, info.ref)
	}

	assert.ElementsMatch(t, []string{rulesRef, yamlRef150}, refs,
		"should bump to yaml-plugin:1.5.0 using resolved reference")
}

func TestPrepareArtifactList_WithDeps_ComplexDependencyGraph(t *testing.T) {
	// Complex scenario:
	// okta-rules:1.0.0 -> okta-plugin:0.3.0 -> json-plugin:0.7.0
	// k8saudit-rules:1.5.0 -> k8saudit-plugin:0.9.0 -> json-plugin:0.6.0
	// cloudtrail-rules:2.0.0 -> cloudtrail-plugin:1.2.0
	// cloudtrail-plugin:1.2.0 -> json-plugin:0.7.0
	//
	// json-plugin should be bumped to 0.7.0 (highest compatible version)
	idxCache := newTestIndexCache(
		&index.Entry{Name: "okta-rules", Registry: "ghcr.io", Repository: "falcosecurity/rules/okta"},
		&index.Entry{Name: "k8saudit-rules", Registry: "ghcr.io", Repository: "falcosecurity/rules/k8saudit"},
		&index.Entry{Name: "cloudtrail-rules", Registry: "ghcr.io", Repository: "falcosecurity/rules/cloudtrail"},
		&index.Entry{Name: "okta-plugin", Registry: "ghcr.io", Repository: "falcosecurity/plugins/okta"},
		&index.Entry{Name: "k8saudit-plugin", Registry: "ghcr.io", Repository: "falcosecurity/plugins/k8saudit"},
		&index.Entry{Name: "cloudtrail-plugin", Registry: "ghcr.io", Repository: "falcosecurity/plugins/cloudtrail"},
		&index.Entry{Name: "json-plugin", Registry: "ghcr.io", Repository: "falcosecurity/plugins/json"},
	)

	o := newTestInstallOptions(t, idxCache, true)

	ctx := context.Background()
	oktaRulesRef, _ := idxCache.ResolveReference("okta-rules:1.0.0")
	k8sRulesRef, _ := idxCache.ResolveReference("k8saudit-rules:1.5.0")
	cloudtrailRulesRef, _ := idxCache.ResolveReference("cloudtrail-rules:2.0.0")
	oktaPluginRef, _ := idxCache.ResolveReference("okta-plugin:0.3.0")
	k8sPluginRef, _ := idxCache.ResolveReference("k8saudit-plugin:0.9.0")
	cloudtrailPluginRef, _ := idxCache.ResolveReference("cloudtrail-plugin:1.2.0")
	jsonRef060, _ := idxCache.ResolveReference("json-plugin:0.6.0")
	jsonRef070, _ := idxCache.ResolveReference("json-plugin:0.7.0")

	provider := &fakeConfigProvider{configs: map[string]*oci.ArtifactConfig{
		oktaRulesRef: {
			Name:         "okta-rules",
			Version:      "1.0.0",
			Dependencies: []oci.ArtifactDependency{{Name: "okta-plugin", Version: "0.3.0"}},
		},
		k8sRulesRef: {
			Name:         "k8saudit-rules",
			Version:      "1.5.0",
			Dependencies: []oci.ArtifactDependency{{Name: "k8saudit-plugin", Version: "0.9.0"}},
		},
		cloudtrailRulesRef: {
			Name:         "cloudtrail-rules",
			Version:      "2.0.0",
			Dependencies: []oci.ArtifactDependency{{Name: "cloudtrail-plugin", Version: "1.2.0"}},
		},
		oktaPluginRef: {
			Name:         "okta-plugin",
			Version:      "0.3.0",
			Dependencies: []oci.ArtifactDependency{{Name: "json-plugin", Version: "0.7.0"}},
		},
		k8sPluginRef: {
			Name:         "k8saudit-plugin",
			Version:      "0.9.0",
			Dependencies: []oci.ArtifactDependency{{Name: "json-plugin", Version: "0.6.0"}},
		},
		cloudtrailPluginRef: {
			Name:         "cloudtrail-plugin",
			Version:      "1.2.0",
			Dependencies: []oci.ArtifactDependency{{Name: "json-plugin", Version: "0.7.0"}},
		},
		jsonRef060: {
			Name:    "json-plugin",
			Version: "0.6.0",
		},
		jsonRef070: {
			Name:    "json-plugin",
			Version: "0.7.0",
		},
	}}

	artifacts, err := o.prepareArtifactList(ctx, provider.ArtifactConfig, []string{
		"okta-rules:1.0.0",
		"k8saudit-rules:1.5.0",
		"cloudtrail-rules:2.0.0",
	})
	require.NoError(t, err)
	assert.Len(t, artifacts, 7, "should resolve all artifacts and shared dependency")

	refs := make([]string, 0, len(artifacts))
	for _, info := range artifacts {
		refs = append(refs, info.ref)
	}

	assert.ElementsMatch(t, []string{
		oktaRulesRef,
		k8sRulesRef,
		cloudtrailRulesRef,
		oktaPluginRef,
		k8sPluginRef,
		cloudtrailPluginRef,
		jsonRef070, // Should be 0.7.0, not 0.6.0
	}, refs, "json-plugin should be bumped to 0.7.0, the highest compatible version")
}
