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

package utils

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

const (
	filename1 = "file1"
	filename2 = "file2"
)

func TestCreateTarGzArchiveFile(t *testing.T) {
	dir := t.TempDir()
	f1, err := os.Create(filepath.Join(dir, filename1))
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer f1.Close()

	tarball, err := CreateTarGzArchive(filepath.Join(dir, filename1))
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer os.Remove(tarball)

	file, err := os.Open(tarball)
	if err != nil {
		t.Fatalf(err.Error())
	}

	paths, err := listHeaders(file)
	fmt.Println(paths)
	if err != nil {
		t.Fatalf(err.Error())
	}

	if len(paths) != 1 {
		t.Fatalf("Expected 1 path, got %d", len(paths))
	}

	base := filepath.Base(paths[0])
	if base != filename1 {
		t.Errorf("Expected file1, got %s", base)
	}
}

func TestCreateTarGzArchiveDir(t *testing.T) {
	// Test that we can compress directories
	dir := t.TempDir()

	// add some files
	f1, err := os.Create(filepath.Join(dir, filename1))
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer f1.Close()
	f2, err := os.Create(filepath.Join(dir, filename2))
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer f2.Close()

	tarball, err := CreateTarGzArchive(dir)
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer os.Remove(tarball)

	file, err := os.Open(tarball)
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer file.Close()

	paths, err := listHeaders(file)
	if err != nil {
		t.Fatalf(err.Error())
	}

	if len(paths) != 3 {
		t.Fatalf("Expected 3 paths, got %d", len(paths))
	}

	p := filepath.Base(paths[0])
	if p != filepath.Base(dir) {
		t.Errorf("Expected %s, got %s", filepath.Base(dir), p)
	}

	p = filepath.Base(paths[1])
	if p != filename1 {
		t.Errorf("Expected file1, got %s", p)
	}

	p = filepath.Base(paths[2])
	if p != filename2 {
		t.Errorf("Expected file2, got %s", p)
	}
}
