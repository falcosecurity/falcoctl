// Copyright 2022 The Falco Authors
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

// ExtractTarGz extracts a *.tar.gz compressed archive and moves its content to destDir.
func ExtractTarGz(gzipStream io.Reader, destDir string) error {
	uncompressedStream, err := gzip.NewReader(gzipStream)
	if err != nil {
		return err
	}

	tarReader := tar.NewReader(uncompressedStream)

	for {
		header, err := tarReader.Next()

		if errors.Is(err, io.EOF) {
			break
		}

		if err != nil {
			return err
		}

		switch header.Typeflag {
		case tar.TypeDir:
			return fmt.Errorf("unexepected dir inside the archive, expected to find only files without any tree structure")
		case tar.TypeReg:
			outFile, err := os.Create(filepath.Clean(filepath.Join(destDir, filepath.Clean(header.Name))))
			if err != nil {
				return err
			}
			if err := copyInChunks(outFile, tarReader); err != nil {
				return err
			}
			err = outFile.Close()
			if err != nil {
				return err
			}

		default:
			return fmt.Errorf("extractTarGz: uknown type: %b in %s", header.Typeflag, header.Name)
		}
	}

	return nil
}

func copyInChunks(dst io.Writer, src io.Reader) error {
	for {
		_, err := io.CopyN(dst, src, 1024)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return err
		}
	}

	return nil
}
