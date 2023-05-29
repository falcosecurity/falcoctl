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

package oci

const (

	// FalcoRulesfileConfigMediaType is the MediaType for rule's config layer.
	FalcoRulesfileConfigMediaType = "application/vnd.cncf.falco.rulesfile.config.v1+json"

	// FalcoRulesfileLayerMediaType is the MediaType for rules.
	FalcoRulesfileLayerMediaType = "application/vnd.cncf.falco.rulesfile.layer.v1+tar.gz"

	// FalcoPluginConfigMediaType is the MediaType for plugin's config layer.
	FalcoPluginConfigMediaType = "application/vnd.cncf.falco.plugin.config.v1+json"

	// FalcoPluginLayerMediaType is the MediaType for plugins.
	FalcoPluginLayerMediaType = "application/vnd.cncf.falco.plugin.layer.v1+tar.gz"

	// DefaultTag is the default tag reference to be used when none is provided.
	DefaultTag = "latest"
)
