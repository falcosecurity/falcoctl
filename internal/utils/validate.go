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
	"fmt"
	"strings"

	"oras.land/oras-go/v2/registry"

	"github.com/falcosecurity/falcoctl/pkg/index"
	"github.com/falcosecurity/falcoctl/pkg/oci"
)

// GetRegistryFromRef extracts the registry from a ref string.
func GetRegistryFromRef(ref string) (string, error) {
	index := strings.Index(ref, "/")
	if index <= 0 {
		return "", fmt.Errorf("cannot extract registry name from ref %q", ref)
	}

	return ref[0:index], nil
}

// TagFromRef extracts the tag values from a ref string.
func TagFromRef(ref string) (string, error) {
	i := strings.Index(ref, ":")
	if i <= 0 {
		return "", fmt.Errorf("cannot extract tag name from ref %q", ref)
	}

	return ref[i+1:], nil
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

// ParseReference is a helper function that parse with the followig logic:
//
//  1. if name is the name of an artifact, it will use the merged index to compute
//     its reference. The tag latest is always appended.
//     e.g "cloudtrail" -> "ghcr.io/falcosecurity/plugins/cloudtrail:latest"
//     if instead a tag or a digest is specified, the name will be used to look up
//     into mergedIndexes, then the tag or digest will be appended.
//     e.g "cloudtrail:0.5.1" -> "ghcr.io/falcosecurity/plugins/cloudtrail:0.5.1"
//     e.g "cloudtrail@sha256:123abc..." -> "ghcr.io/falcosecurity/plugins/cloudtrail@sha256:123abc...
//
//  2. if name is a reference without tag or digest, tag latest is appended.
//     e.g. "ghcr.io/falcosecurity/plugins/cloudtrail" -> "ghcr.io/falcosecurity/plugins/cloudtrail:latest"
//
//  3. if name is a complete reference, it will be returned as is.
func ParseReference(mergedIndexes *index.MergedIndexes, name string) (string, error) {
	parsedRef, err := registry.ParseReference(name)
	var ref string

	switch {
	case err != nil:
		var entryName, tag, digest string

		switch {
		case !strings.ContainsAny(name, ":@"):
			entryName = name
		case strings.Contains(name, ":") && !strings.Contains(name, "@"):
			splittedName := strings.Split(name, ":")
			entryName = splittedName[0]
			tag = splittedName[1]
		case strings.Contains(name, "@"):
			splittedName := strings.Split(name, "@")
			entryName = splittedName[0]
			digest = splittedName[1]
		default:
			return "", fmt.Errorf("cannot parse %q", name)
		}

		entry, ok := mergedIndexes.EntryByName(entryName)
		if !ok {
			return "", fmt.Errorf("cannot find %s among the configured indexes, skipping", name)
		}

		ref = fmt.Sprintf("%s/%s", entry.Registry, entry.Repository)
		switch {
		case tag == "" && digest == "":
			ref += ":" + oci.DefaultTag
		case tag != "":
			ref += ":" + tag
		case digest != "":
			ref += "@" + digest
		}

	case parsedRef.Reference == "":
		parsedRef.Reference = oci.DefaultTag
		ref = parsedRef.String()

	default:
		ref = parsedRef.String()
	}

	return ref, nil
}
