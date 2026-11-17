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

package oci

import (
	"reflect"
	"testing"

	v1 "github.com/opencontainers/image-spec/specs-go/v1"
)

// TestPlatformsFromIndexSkipsEntriesWithoutPlatform covers an image index that
// carries an entry with no platform, which the spec allows (an attestation or
// referrers entry, for example). Descriptor.Platform is a pointer, so before the
// nil check such an entry was dereferenced and crashed the caller with a nil
// pointer panic.
func TestPlatformsFromIndexSkipsEntriesWithoutPlatform(t *testing.T) {
	index := &v1.Index{
		MediaType: v1.MediaTypeImageIndex,
		Manifests: []v1.Descriptor{
			{
				// no platform, for instance an attestation or referrers entry
				MediaType: v1.MediaTypeImageManifest,
			},
			{
				MediaType: v1.MediaTypeImageManifest,
				Platform:  &v1.Platform{OS: "linux", Architecture: "amd64"},
			},
			{
				MediaType: v1.MediaTypeImageManifest,
				Platform:  &v1.Platform{OS: "linux", Architecture: "arm64"},
			},
		},
	}

	got := platformsFromIndex(index)

	want := map[string]struct{}{
		"linux-amd64": {},
		"linux-arm64": {},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected platforms: got %v, want %v", got, want)
	}
}
