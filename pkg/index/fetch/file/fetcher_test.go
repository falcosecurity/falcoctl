// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 The Falco Authors
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

package file

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"

	"github.com/falcosecurity/falcoctl/pkg/index/config"
	"github.com/falcosecurity/falcoctl/pkg/index/index"
)

func TestFileFetchWithValidFile(t *testing.T) {
	filename := "TestFileFetchWithValidFile-filename.yaml"
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

	configDir := t.TempDir()
	configFile := filepath.Join(configDir, filename)

	entryBytes, err := yaml.Marshal(entries)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	err = os.WriteFile(configFile, entryBytes, os.FileMode(0o644))
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	b, err := Fetch(ctx, &config.Entry{
		Name:    "test",
		URL:     fmt.Sprintf("file://%s/%s", configDir, filename),
		Backend: "GCS",
	})

	assert.NoError(t, err, "error should not occur")
	assert.NotNil(t, b, "returned bytes should not be nil")
	var resultEntries []index.Entry
	err = yaml.Unmarshal(b, &resultEntries)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	assert.Equal(t, entries, resultEntries)
}

func TestFileFetchWithNonExistentFile(t *testing.T) {
	filename := "TestFileFetchWithNonExistentFile-filename.yaml"

	ctx := context.Background()

	configDir := t.TempDir()
	// We intentionally do not write out the file here

	_, err := Fetch(ctx, &config.Entry{
		Name:    "test",
		URL:     fmt.Sprintf("file://%s/%s", configDir, filename),
		Backend: "GCS",
	})

	expectedError := fmt.Sprintf("reading file: open %s/%s: no such file or directory", configDir, filename)
	assert.EqualError(t, err, expectedError)
}
