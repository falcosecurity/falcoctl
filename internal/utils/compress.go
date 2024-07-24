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
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// TmpDirPrefix prefix used for the temporary directory where the tar.gz archives live before pushing
// to the OCI registry.
const TmpDirPrefix = "falcoctl-registry-push-"

// CreateTarGzArchive compresses and saves in a tar archive the passed file.
func CreateTarGzArchive(dir, path string, stripComponents bool) (file string, err error) {
	cleanedPath := filepath.Clean(path)
	if dir == "" {
		dir = TmpDirPrefix
	}
	// Create output file.
	tmpDir, err := os.MkdirTemp("", dir)
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

	if fInfo.IsDir() {
		// write header of the directory
		header, err := tar.FileInfoHeader(fInfo, path)
		if err != nil {
			return "", err
		}

		if err = tw.WriteHeader(header); err != nil {
			return "", err
		}

		// walk files in the directory and copy to .tar.gz
		err = filepath.Walk(path, func(path string, info fs.FileInfo, err error) error {
			if err != nil {
				return err
			}

			if info.IsDir() {
				return nil
			}

			return copyToTarGz(path, tw, info, stripComponents)
		})
		if err != nil {
			return "", err
		}
	} else {
		if err = copyToTarGz(path, tw, fInfo, stripComponents); err != nil {
			return "", err
		}
	}

	return outFile.Name(), err
}

func copyToTarGz(path string, tw *tar.Writer, info fs.FileInfo, stripComponents bool) error {
	var headerName string

	if stripComponents {
		headerName = filepath.Base(path)
	} else {
		headerName = path
	}

	header := &tar.Header{
		Name:     headerName,
		Size:     info.Size(),
		Mode:     int64(info.Mode()),
		Typeflag: tar.TypeReg,
	}

	// write the header
	if err := tw.WriteHeader(header); err != nil {
		return err
	}

	f, err := os.Open(path)
	if err != nil {
		return err
	}

	// copy file data into tar writer
	if _, err = io.CopyN(tw, f, info.Size()); err != nil {
		return err
	}

	return nil
}
