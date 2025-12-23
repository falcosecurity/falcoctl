// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025 The Falco Authors
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

package artifactstate

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteAndRead(t *testing.T) {
	baseDir := t.TempDir()
	ref := "ghcr.io/falcosecurity/rules/falco-rules:latest"
	digest := "sha256:1234567890abcdef"

	// Test Write
	err := Write(baseDir, ref, digest)
	require.NoError(t, err)

	// Verify file was created
	path := filePath(baseDir, ref)
	assert.FileExists(t, path)

	// Test Read
	readDigest, ok, err := Read(baseDir, ref)
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, digest, readDigest)
}

func TestReadNonExistent(t *testing.T) {
	baseDir := t.TempDir()
	ref := "ghcr.io/falcosecurity/rules/non-existent:latest"

	digest, ok, err := Read(baseDir, ref)
	require.NoError(t, err)
	assert.False(t, ok)
	assert.Empty(t, digest)
}

func TestWriteEmptyParameters(t *testing.T) {
	tests := []struct {
		name    string
		baseDir string
		ref     string
		digest  string
	}{
		{
			name:    "empty baseDir",
			baseDir: "",
			ref:     "test:latest",
			digest:  "sha256:abc",
		},
		{
			name:    "empty ref",
			baseDir: t.TempDir(),
			ref:     "",
			digest:  "sha256:abc",
		},
		{
			name:    "empty digest",
			baseDir: t.TempDir(),
			ref:     "test:latest",
			digest:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Write(tt.baseDir, tt.ref, tt.digest)
			require.Error(t, err)
			assert.True(t, errors.Is(err, ErrInvalidWriteArgs))
		})
	}
}

func TestReadEmptyParameters(t *testing.T) {
	tests := []struct {
		name    string
		baseDir string
		ref     string
	}{
		{
			name:    "empty baseDir",
			baseDir: "",
			ref:     "test:latest",
		},
		{
			name:    "empty ref",
			baseDir: t.TempDir(),
			ref:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			digest, ok, err := Read(tt.baseDir, tt.ref)
			require.Error(t, err)
			assert.True(t, errors.Is(err, ErrInvalidReadArgs))
			assert.False(t, ok)
			assert.Empty(t, digest)
		})
	}
}

func TestWriteCreatesDirectoryStructure(t *testing.T) {
	baseDir := t.TempDir()
	ref := "ghcr.io/falcosecurity/plugins/plugin:tag"
	digest := "sha256:fedcba9876543210"

	err := Write(baseDir, ref, digest)
	require.NoError(t, err)

	// Verify directory structure was created
	stateDir := filepath.Join(baseDir, dirName, subDir)
	info, err := os.Stat(stateDir)
	require.NoError(t, err)
	assert.True(t, info.IsDir())
	// On unix, umask may mask group/other bits: assert at least user rwx.
	assert.Equal(t, os.FileMode(dirPerm), info.Mode().Perm()&0o700)
}

func TestReadCorruptedFile(t *testing.T) {
	baseDir := t.TempDir()
	ref := "ghcr.io/falcosecurity/rules/corrupted:latest"

	// Create a corrupted state file
	path := filePath(baseDir, ref)
	err := os.MkdirAll(filepath.Dir(path), dirPerm)
	require.NoError(t, err)
	err = os.WriteFile(path, []byte("not valid json"), filePerm)
	require.NoError(t, err)

	digest, ok, err := Read(baseDir, ref)
	require.Error(t, err)
	assert.False(t, ok)
	assert.Empty(t, digest)
}

func TestReadEmptyDigest(t *testing.T) {
	baseDir := t.TempDir()
	ref := "ghcr.io/falcosecurity/rules/empty-digest:latest"

	// Write a state with empty digest
	err := Write(baseDir, ref, "sha256:test")
	require.NoError(t, err)

	// Manually overwrite with empty digest
	path := filePath(baseDir, ref)
	err = os.WriteFile(path, []byte(`{"ref":"test","digest":"","updatedAt":"2025-12-22T00:00:00Z"}`), filePerm)
	require.NoError(t, err)

	digest, ok, err := Read(baseDir, ref)
	require.NoError(t, err)
	assert.False(t, ok)
	assert.Empty(t, digest)
}

func TestMultipleRefsInSameBaseDir(t *testing.T) {
	baseDir := t.TempDir()

	refs := []struct {
		ref    string
		digest string
	}{
		{"ghcr.io/falcosecurity/rules/falco-rules:latest", "sha256:111111"},
		{"ghcr.io/falcosecurity/plugins/k8saudit:0.5.0", "sha256:222222"},
		{"ghcr.io/falcosecurity/rules/application-rules:3.0", "sha256:333333"},
	}

	// Write all refs
	for _, r := range refs {
		err := Write(baseDir, r.ref, r.digest)
		require.NoError(t, err)
	}

	// Read and verify all refs
	for _, r := range refs {
		digest, ok, err := Read(baseDir, r.ref)
		require.NoError(t, err)
		assert.True(t, ok)
		assert.Equal(t, r.digest, digest)
	}
}

func TestFilePathUniqueness(t *testing.T) {
	baseDir := t.TempDir()

	// Two different refs should generate different file paths
	ref1 := "ghcr.io/falcosecurity/rules/falco-rules:latest-v2"
	ref2 := "ghcr.io/falcosecurity/rules/falco-rules:v1"

	path1 := filePath(baseDir, ref1)
	path2 := filePath(baseDir, ref2)

	assert.NotEqual(t, path1, path2, "Different refs should generate different file paths")
}
