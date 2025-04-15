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
	"strings"
)

// GetRegistryFromRef extracts the registry from a ref string.
func GetRegistryFromRef(ref string) (string, error) {
	// Remove scheme if present
	ref = strings.TrimPrefix(strings.TrimPrefix(ref, "http://"), "https://")

	index := strings.Index(ref, "/")
	if index <= 0 {
		return "", fmt.Errorf("cannot extract registry name from ref %q", ref)
	}

	return ref[0:index], nil
}

// RepositoryFromRef extracts the registry+repository from a ref string.
func RepositoryFromRef(ref string) (string, error) {
	name, err := NameFromRef(ref)
	if err != nil {
		return "", fmt.Errorf("cannot extract artifact repository: %w", err)
	}

	parts := strings.Split(ref, "/")
	return strings.Join(append(parts[:len(parts)-1], name), "/"), nil
}

// NameFromRef extracts the name of the artifact from a ref string.
func NameFromRef(ref string) (string, error) {
	// todo: check and improve parsing logic
	parts := strings.Split(ref, "/")
	parts = strings.Split(parts[len(parts)-1], "@")
	parts = strings.Split(parts[0], ":")
	if parts[0] == "" {
		return "", fmt.Errorf(`cannot extract artifact name from reference: %q`, ref)
	}

	return parts[0], nil
}
