// Copyright 2023 The Falco Authors
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

package gcs

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"

	"github.com/falcosecurity/falcoctl/pkg/index/config"
	"github.com/falcosecurity/falcoctl/pkg/index/index"
)

func TestGCSFetchWithValidResponse(t *testing.T) {
	bucket := "bucket"
	object := "object/path"
	entries := []index.Entry{{
		Name:       "test",
		Type:       "rulesfile",
		Registry:   "test.io",
		Repository: "test",
		Maintainers: index.Maintainer{
			{
				Email: "test@local",
				Name:  "test",
			},
		},
		Sources:  []string{"/test"},
		Keywords: []string{"test"},
	}}

	ctx := context.Background()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !assert.Equal(t, http.MethodGet, r.Method) {
			return
		}

		expectedPath := fmt.Sprintf("/%s/%s", bucket, object)
		if !assert.Equal(t, expectedPath, r.URL.Path) {
			return
		}

		entryBytes, err := yaml.Marshal(entries)
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}

		_, err = w.Write(entryBytes)
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
	}))

	// Set STORAGE_EMULATOR_HOST environment variable.
	err := os.Setenv("STORAGE_EMULATOR_HOST", server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	b, err := Fetch(ctx, &config.Entry{
		Name:    "test",
		URL:     fmt.Sprintf("gs://%s/%s", bucket, object),
		Backend: "GCS",
	})
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	assert.NotNil(t, b, "returned index bytes should not be nil")
	var resultEntries []index.Entry
	err = yaml.Unmarshal(b, &resultEntries)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	assert.Equal(t, entries, resultEntries)
}

func TestGCSFetchWithNonExistentObject(t *testing.T) {
	bucket := "this-bucket"
	object := "does/not/exist"

	ctx := context.Background()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !assert.Equal(t, http.MethodGet, r.Method) {
			return
		}

		expectedPath := fmt.Sprintf("/%s/%s", bucket, object)
		if !assert.Equal(t, expectedPath, r.URL.Path) {
			return
		}

		w.WriteHeader(http.StatusNotFound)

		_, err := fmt.Fprintf(w, `
		{
			"error": {
			  "code": 404,
			  "message": "No such object: %s",
			  "errors": [
				{
				  "message": "No such object: %s",
				  "domain": "global",
				  "reason": "notFound"
				}
			  ]
			}
		}`, expectedPath, expectedPath)

		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
	}))

	// Set STORAGE_EMULATOR_HOST environment variable.
	err := os.Setenv("STORAGE_EMULATOR_HOST", server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	b, err := Fetch(ctx, &config.Entry{
		Name:    "test",
		URL:     fmt.Sprintf("gs://%s/%s", bucket, object),
		Backend: "GCS",
	})

	assert.ErrorContains(t, err, "storage: object doesn't exist", "fetch should have errored with object not found")
	assert.Nil(t, b, "returned index should be nil")
}

func TestGCSFetchWithUnauthorized(t *testing.T) {
	bucket := "some-bucket"
	object := "no/access"

	ctx := context.Background()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !assert.Equal(t, http.MethodGet, r.Method) {
			return
		}

		expectedPath := fmt.Sprintf("/%s/%s", bucket, object)
		if !assert.Equal(t, expectedPath, r.URL.Path) {
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		w.Header().Add("www-authenticate", "Bearer realm=\"https://accounts.google.com/\"")
		_, err := w.Write([]byte(`{
  "error": {
    "code": 401,
    "message": "Anonymous caller does not have storage.objects.get access to the Google Cloud Storage object. ` +
			`Permission 'storage.objects.get' denied on resource (or it may not exist).",
    "errors": [
    {
      "message": "Anonymous caller does not have storage.objects.get access to the Google Cloud Storage object. ` +
			`Permission 'storage.objects.get' denied on resource (or it may not exist).",
      "domain": "global",
      "reason": "required",
      "locationType": "header",
      "location": "Authorization"
    }
    ]
  }
}`))
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
	}))

	// Set STORAGE_EMULATOR_HOST environment variable.
	err := os.Setenv("STORAGE_EMULATOR_HOST", server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	b, err := Fetch(ctx, &config.Entry{
		Name:    "test",
		URL:     fmt.Sprintf("gs://%s/%s", bucket, object),
		Backend: "GCS",
	})

	assert.ErrorContains(t, err, "Permission 'storage.objects.get' denied on resource", "fetch should have errored with permission denied")
	assert.Nil(t, b, "returned index should be nil")
}
