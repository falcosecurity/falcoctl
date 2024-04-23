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

package utils

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/net/context"
)

const (
	srcDir = "./foo"
)

var (
	files = []string{srcDir + "/example.txt", srcDir + "/test.txt", srcDir + "/bar/baz.txt"}
)

func createTarball(t *testing.T, tarballFilePath, srcDir string) {
	file, err := os.Create(tarballFilePath)
	assert.NoError(t, err)
	defer file.Close()

	gzipWriter := gzip.NewWriter(file)
	defer gzipWriter.Close()

	tarWriter := tar.NewWriter(gzipWriter)
	defer tarWriter.Close()

	err = filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		return addToArchive(tarWriter, path, info)
	})
	assert.NoError(t, err)
}

func addToArchive(tw *tar.Writer, fullName string, info os.FileInfo) error {
	// Open the file which will be written into the archive
	file, err := os.Open(fullName)
	if err != nil {
		return err
	}
	defer file.Close()

	// Create a tar Header from the FileInfo data
	header, err := tar.FileInfoHeader(info, info.Name())
	if err != nil {
		return err
	}

	// Use full path as name (FileInfoHeader only takes the basename)
	// If we don't do this the directory strucuture would
	// not be preserved
	// https://golang.org/src/archive/tar/common.go?#L626
	header.Name = fullName

	// Write file header to the tar archive
	err = tw.WriteHeader(header)
	if err != nil {
		return err
	}

	if !info.IsDir() {
		// Copy file content to tar archive
		_, err = io.Copy(tw, file)
		if err != nil {
			return err
		}
	}

	return nil
}

func TestExtractTarGz(t *testing.T) {
	// Create src dir
	err := os.MkdirAll(srcDir, 0o750)
	assert.NoError(t, err)
	t.Cleanup(func() {
		_ = os.RemoveAll(srcDir)
	})

	// Generate files to be tarballed
	for _, f := range files {
		err := os.MkdirAll(filepath.Dir(f), 0o755)
		assert.NoError(t, err)
		_, err = os.Create(f)
		assert.NoError(t, err)
	}

	// create tarball
	createTarball(t, "./test.tgz", srcDir)
	t.Cleanup(func() {
		_ = os.RemoveAll("./test.tgz")
	})

	// Create dest folder
	destDir := "./test"
	err = os.MkdirAll(destDir, 0o750)
	assert.NoError(t, err)
	t.Cleanup(func() {
		_ = os.RemoveAll(destDir)
	})

	// Extract tarball
	f, err := os.Open("./test.tgz")
	assert.NoError(t, err)
	t.Cleanup(func() {
		f.Close()
	})

	list, err := ExtractTarGz(context.TODO(), f, destDir, 0)
	assert.NoError(t, err)

	// Final checks
	assert.NotEmpty(t, list)

	// All extracted files are ok
	for _, f := range list {
		_, err := os.Stat(f)
		assert.NoError(t, err)
	}

	// Extracted folder contains all source files (plus folders)
	absDestDir, err := filepath.Abs(destDir)
	assert.NoError(t, err)
	for _, f := range files {
		path := filepath.Join(absDestDir, f)
		assert.Contains(t, list, path)
	}
}

func TestExtractTarGzStripComponents(t *testing.T) {
	// Create src dir
	srcDir := "./foo"
	err := os.MkdirAll(srcDir, 0o750)
	assert.NoError(t, err)
	t.Cleanup(func() {
		_ = os.RemoveAll(srcDir)
	})

	// Generate files to be tarballed
	for _, f := range files {
		err := os.MkdirAll(filepath.Dir(f), 0o755)
		assert.NoError(t, err)
		_, err = os.Create(f)
		assert.NoError(t, err)
	}

	// create tarball
	createTarball(t, "./test.tgz", srcDir)
	t.Cleanup(func() {
		_ = os.RemoveAll("./test.tgz")
	})

	// Create dest folder
	destdirStrip := "./test_strip"
	err = os.MkdirAll(destdirStrip, 0o750)
	assert.NoError(t, err)
	t.Cleanup(func() {
		_ = os.RemoveAll(destdirStrip)
	})

	// Extract tarball
	f, err := os.Open("./test.tgz")
	assert.NoError(t, err)
	t.Cleanup(func() {
		f.Close()
	})
	// NOTE that here we strip first component
	list, err := ExtractTarGz(context.TODO(), f, destdirStrip, 1)
	assert.NoError(t, err)

	// Final checks
	assert.NotEmpty(t, list)

	// All extracted files are ok
	for _, f := range list {
		_, err := os.Stat(f)
		assert.NoError(t, err)
	}

	// Extracted folder contains all source files (plus folders)
	absDestDirStrip, err := filepath.Abs(destdirStrip)
	assert.NoError(t, err)
	for _, f := range files {
		// We stripped first component (ie: srcDir)
		ff := strings.TrimPrefix(f, srcDir)
		path := filepath.Join(absDestDirStrip, ff)
		assert.Contains(t, list, path)
	}
}
