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
	"strings"

	"github.com/falcosecurity/falcoctl/pkg/oci"
)

// ExtractTarGz extracts a *.tar.gz compressed archive and moves its content to destDir.
// Returns a slice containing the full path of the extracted files.
func ExtractTarGz(gzipStream io.Reader, destDir string, artifactType oci.ArtifactType, stripPathComponents int) ([]string, error) {
	var files []string

	uncompressedStream, err := gzip.NewReader(gzipStream)
	if err != nil {
		return nil, err
	}

	tarReader := tar.NewReader(uncompressedStream)

	for {
		header, err := tarReader.Next()

		if errors.Is(err, io.EOF) {
			break
		}

		if err != nil {
			return nil, err
		}

		if strings.Contains(header.Name, "..") {
			return nil, fmt.Errorf("not allowed relative path in tar archive")
		}

		strippedName := stripComponents(header.Name, stripPathComponents)

		switch header.Typeflag {
		case tar.TypeDir:
			if artifactType == oci.Plugin || artifactType == oci.Rulesfile {
				return nil, fmt.Errorf("unexepected dir inside the archive, "+
					"expected to find only files without any tree structure for %q artifacts", artifactType.String())
			} else if artifactType == oci.Asset {
				d := filepath.Join(destDir, strippedName)
				if err = os.Mkdir(filepath.Clean(d), 0o750); err != nil {
					return nil, err
				}
				files = append(files, d)
			}
		case tar.TypeReg:
			f := filepath.Join(destDir, strippedName)
			outFile, err := os.Create(filepath.Clean(f))
			if err != nil {
				return nil, err
			}
			if written, err := io.CopyN(outFile, tarReader, header.Size); err != nil {
				return nil, err
			} else if written != header.Size {
				return nil, io.ErrShortWrite
			}
			if err = outFile.Close(); err != nil {
				return nil, err
			}
			files = append(files, f)

		default:
			return nil, fmt.Errorf("extractTarGz: uknown type: %b in %s", header.Typeflag, header.Name)
		}
	}

	return files, nil
}

func stripComponents(headerName string, stripComponents int) string {
	if stripComponents == 0 {
		return headerName
	}
	names := strings.FieldsFunc(headerName, func(r rune) bool {
		return r == os.PathSeparator
	})
	if len(names) < stripComponents {
		return headerName
	}
	return filepath.Clean(strings.Join(names[stripComponents:], "/"))
}

func listHeaders(gzipStream io.Reader) {
	uncompressedStream, err := gzip.NewReader(gzipStream)
	if err != nil {
		return
	}

	tarReader := tar.NewReader(uncompressedStream)

	for {
		header, err := tarReader.Next()

		if errors.Is(err, io.EOF) {
			break
		}

		if err != nil {
			return
		}

		fmt.Println(header.Name)
	}
}
