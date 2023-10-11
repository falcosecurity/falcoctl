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
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// ErrNotTarGz returned when the file is not a tar.gz archive.
var ErrNotTarGz = errors.New("not a tar.gz archive")

// IsTarGz checks if the file is of type tar.gz.
func IsTarGz(fileName string) error {
	f, err := os.Open(filepath.Clean(fileName))
	if err != nil {
		return err
	}
	// Check if the file is gzip compressed.
	uncompressedStream, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("%s: %w", err.Error(), ErrNotTarGz)
	}

	tarReader := tar.NewReader(uncompressedStream)

	// Loop through the files and check if the header is ok.
	// If the files are not in tar format it will error.
	for {
		_, err = tarReader.Next()

		if errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return fmt.Errorf("%s: %w", err.Error(), ErrNotTarGz)
		}
	}

	return nil
}
