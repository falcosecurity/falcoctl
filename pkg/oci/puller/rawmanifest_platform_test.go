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

package puller_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/opencontainers/go-digest"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/registry/remote/auth"

	"github.com/falcosecurity/falcoctl/pkg/oci/authn"
	ocipuller "github.com/falcosecurity/falcoctl/pkg/oci/puller"
)

// TestRawManifestIndexEntryWithoutPlatform covers an image index that carries an
// entry with no platform, which the spec allows. Before the nil check that entry
// was dereferenced while looking for a match and crashed the caller.
func TestRawManifestIndexEntryWithoutPlatform(t *testing.T) {
	manifest := v1.Manifest{
		MediaType: v1.MediaTypeImageManifest,
		Config:    v1.Descriptor{MediaType: v1.MediaTypeImageConfig, Size: 2, Digest: digestOf([]byte("{}"))},
	}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}

	index := v1.Index{
		MediaType: v1.MediaTypeImageIndex,
		Manifests: []v1.Descriptor{
			{
				// no platform, for instance an attestation or referrers entry
				MediaType: v1.MediaTypeImageManifest,
				Digest:    digestOf(manifestBytes),
				Size:      int64(len(manifestBytes)),
			},
			{
				MediaType: v1.MediaTypeImageManifest,
				Digest:    digestOf(manifestBytes),
				Size:      int64(len(manifestBytes)),
				Platform:  &v1.Platform{OS: "linux", Architecture: "amd64"},
			},
		},
	}
	indexBytes, err := json.Marshal(index)
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v2/":
			w.WriteHeader(http.StatusOK)
		case strings.HasSuffix(r.URL.Path, "/manifests/latest"):
			w.Header().Set("Content-Type", v1.MediaTypeImageIndex)
			w.Header().Set("Docker-Content-Digest", digestOf(indexBytes).String())
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(indexBytes)
		case strings.Contains(r.URL.Path, "/manifests/"):
			w.Header().Set("Content-Type", v1.MediaTypeImageManifest)
			w.Header().Set("Docker-Content-Digest", digestOf(manifestBytes).String())
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(manifestBytes)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	ref := fmt.Sprintf("%s/test/artifact:latest", strings.TrimPrefix(server.URL, "http://"))
	puller := ocipuller.NewPuller(authn.NewClient(authn.WithCredentials(&auth.EmptyCredential)), true, nil)

	got, err := puller.RawManifest(context.Background(), ref, "linux", "amd64")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) == 0 {
		t.Fatal("expected a manifest, got nothing")
	}
}

func digestOf(b []byte) digest.Digest {
	sum := sha256.Sum256(b)
	return digest.Digest("sha256:" + hex.EncodeToString(sum[:]))
}
