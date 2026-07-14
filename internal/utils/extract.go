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

	"golang.org/x/net/context"
)

// ExtractTarGz extracts a *.tar.gz compressed archive and moves its content to destDir.
// Returns a slice containing the full path of the extracted files.
func ExtractTarGz(ctx context.Context, gzipStream io.Reader, destDir string, stripPathComponents int) ([]string, error) {
	var (
		files []string
		err   error
	)

	// We need an absolute path
	destDir, err = filepath.Abs(destDir)
	if err != nil {
		return nil, err
	}

	uncompressedStream, err := gzip.NewReader(gzipStream)
	if err != nil {
		return nil, err
	}

	tarReader := tar.NewReader(uncompressedStream)
	for {
		select {
		case <-ctx.Done():
			return nil, errors.New("interrupted")
		default:
		}

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

		path := header.Name
		if stripPathComponents > 0 {
			path = stripComponents(path, stripPathComponents)
		}
		if path == "" {
			continue
		}

		if path, err = safeConcat(destDir, filepath.Clean(path)); err != nil {
			// Skip paths that would escape destDir
			continue
		}
		info := header.FileInfo()

		switch header.Typeflag {
		case tar.TypeDir:
			if err = os.MkdirAll(path, info.Mode()); err != nil {
				return nil, err
			}
		case tar.TypeReg:
			outFile, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, info.Mode())
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
			files = append(files, path)
		case tar.TypeSymlink, tar.TypeLink:
			// Artifacts do not need symlink or hardlink entries, and an unvalidated
			// link target can point outside destDir: the ".." check above only
			// inspects header.Name, never header.Linkname. Reject link entries.
			return nil, fmt.Errorf("link entries are not allowed in artifact archives: %q -> %q", header.Name, header.Linkname)
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
	names := strings.Split(headerName, string(filepath.Separator))
	if len(names) < stripComponents {
		return headerName
	}
	return filepath.Clean(strings.Join(names[stripComponents:], string(filepath.Separator)))
}

// safeConcat concatenates destDir and name
// but returns an error  if the resulting path points outside 'destDir'.
func safeConcat(destDir, name string) (string, error) {
	res := filepath.Join(destDir, name)
	if !strings.HasSuffix(destDir, string(os.PathSeparator)) {
		destDir += string(os.PathSeparator)
	}
	if !strings.HasPrefix(res, destDir) {
		return res, fmt.Errorf("unsafe path concatenation: '%s' with '%s'", destDir, name)
	}
	return res, nil
}
