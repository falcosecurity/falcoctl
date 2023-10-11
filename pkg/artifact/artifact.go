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

package artifact

import (
	"errors"
	"regexp"
	"strings"
)

// inherited from the plugin naming convention, see: https://github.com/falcosecurity/plugins#registering-a-new-plugin
var nameRgx = regexp.MustCompile(`^[a-z]+[a-z0-9-_]*$`)

// see: https://semver.org/#is-there-a-suggested-regular-expression-regex-to-check-a-semver-string
var semVerRgx = regexp.MustCompile(
	`^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?$`,
)

// Artifacts errors.
var (
	ErrInvalidName    = errors.New(`invalid artifact name (must match "[a-z]+[a-z0-9-_]*)"`)
	ErrInvalidVersion = errors.New(`invalid artifact version (must be a valid semver string)`)
	ErrInvalidRef     = errors.New(`invalid artifact reference (must be in the format "name:version")`)
)

// Artifact represents a generic artifact release.
type Artifact struct {
	Name    string
	Version string
}

// ValidateName returns an error if the given name is not a valid artifact name.
func ValidateName(name string) error {
	if !nameRgx.MatchString(name) {
		return ErrInvalidName
	}
	return nil
}

// ValidateVersion returns an error if the given name is not a valid artifact version.
//
// Artifact version must be a semver string (see https://semver.org/).
func ValidateVersion(ver string) error {
	if !semVerRgx.MatchString(ver) {
		return ErrInvalidVersion
	}
	return nil
}

// New returns a new valid Artifact.
//
// Return an error if the given name or version are not valid.
func New(name, version string) (*Artifact, error) {
	if err := ValidateName(name); err != nil {
		return nil, err
	}
	if err := ValidateVersion(version); err != nil {
		return nil, err
	}
	return &Artifact{
		Name:    name,
		Version: version,
	}, nil
}

// ParseRef returns a new valid Artifact from a given reference
// in the "name:version" format.
//
// Return an error if the given reference is not valid.
func ParseRef(artifactRef string) (*Artifact, error) {
	parts := strings.Split(artifactRef, ":")
	if len(parts) != 2 {
		return nil, ErrInvalidRef
	}
	return New(parts[0], parts[1])
}
