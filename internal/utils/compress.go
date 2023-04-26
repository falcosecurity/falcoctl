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

package utils

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// TmpDirPrefix prefix used for the temporary directory where the tar.gz archives live before pushing
// to the OCI registry.
const TmpDirPrefix = "falcoctl-registry-push"

// CreateTarGzArchive compresses and saves in a tar archive the passed file.
func CreateTarGzArchive(path string) (file string, err error) {
	cleanedPath := filepath.Clean(path)
	// Create output file.
	tmpDir, err := os.MkdirTemp("", TmpDirPrefix)
	if err != nil {
		return "", err
	}
	nameTokens := strings.Split(filepath.Base(path), ".")
	outFile, err := os.Create(filepath.Clean(filepath.Join(tmpDir, nameTokens[0]+".tar.gz")))
	if err != nil {
		return "", err
	}

	fInfo, err := os.Stat(cleanedPath)
	if err != nil {
		return "", err
	}

	header, err := tar.FileInfoHeader(fInfo, fInfo.Name())
	if err != nil {
		return "", err
	}

	// Create new writer for gzip.
	gzw := gzip.NewWriter(outFile)
	defer func() {
		if err == nil {
			err = gzw.Close()
		} else {
			if errDefer := gzw.Close(); errDefer != nil {
				err = fmt.Errorf("%s: %w", err.Error(), errDefer)
			}
		}
	}()

	tw := tar.NewWriter(gzw)
	defer func() {
		if err == nil {
			err = tw.Close()
		} else {
			if errDefer := tw.Close(); errDefer != nil {
				err = fmt.Errorf("%s: %w", err.Error(), errDefer)
			}
		}
	}()

	// write the header
	if err = tw.WriteHeader(header); err != nil {
		return "", err
	}

	f, err := os.Open(path)
	if err != nil {
		return "", err
	}

	// copy file data into tar writer
	if _, err = io.Copy(tw, f); err != nil {
		return "", err
	}

	return outFile.Name(), err
}
