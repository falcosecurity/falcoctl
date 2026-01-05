// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The Falco Authors
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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	dirName  = ".falcoctl"
	subDir   = "artifact-state"
	filePerm = 0o600
	dirPerm  = 0o700
)

// State represents the persisted state of an artifact.
type State struct {
	Ref       string    `json:"ref"`
	Digest    string    `json:"digest"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// ErrInvalidWriteArgs is returned when Write is called with invalid (empty) arguments.
var ErrInvalidWriteArgs = errors.New("invalid artifact state write args")

// ErrInvalidReadArgs is returned when Read is called with invalid (empty) arguments.
var ErrInvalidReadArgs = errors.New("invalid artifact state read args")

func filePath(baseDir, ref string) string {
	sum := sha256.Sum256([]byte(ref))
	name := hex.EncodeToString(sum[:]) + ".json"
	return filepath.Join(baseDir, dirName, subDir, name)
}

// Read loads the persisted state for the given artifact ref from disk.
func Read(baseDir, ref string) (digest string, ok bool, err error) {
	if baseDir == "" || ref == "" {
		return "", false, fmt.Errorf("%w: empty argument", ErrInvalidReadArgs)
	}

	b, err := os.ReadFile(filePath(baseDir, ref))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", false, nil
		}
		return "", false, err
	}

	var st State
	if err := json.Unmarshal(b, &st); err != nil {
		return "", false, err
	}
	if st.Digest == "" {
		return "", false, nil
	}
	return st.Digest, true, nil
}

// Write persists the state for the given artifact ref to disk.
func Write(baseDir, ref, digest string) error {
	if baseDir == "" || ref == "" || digest == "" {
		return fmt.Errorf("%w: empty argument", ErrInvalidWriteArgs)
	}

	path := filePath(baseDir, ref)
	if err := os.MkdirAll(filepath.Dir(path), dirPerm); err != nil {
		return err
	}

	st := State{
		Ref:       ref,
		Digest:    digest,
		UpdatedAt: time.Now().UTC(),
	}
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}

	return os.WriteFile(path, b, filePerm)
}
