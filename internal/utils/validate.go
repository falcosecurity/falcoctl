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
	"context"
	"fmt"
	"net/http"
	"reflect"
	"strings"

	"oras.land/oras-go/v2/registry"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"

	"github.com/falcosecurity/falcoctl/pkg/index"
	"github.com/falcosecurity/falcoctl/pkg/oci"
	"github.com/falcosecurity/falcoctl/pkg/oci/authn"
	"github.com/falcosecurity/falcoctl/pkg/output"
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

// CheckRegistryConnection checks whether the registry implement Docker Registry API V2 or
// OCI Distribution Specification. It also checks authentication if credentials are not empty.
func CheckRegistryConnection(ctx context.Context, cred *auth.Credential, regName string, printer *output.Printer) error {
	sp, _ := printer.Spinner.Start(fmt.Sprintf("INFO: Checking connection to remote registry %q", regName))

	if reflect.DeepEqual(*cred, auth.EmptyCredential) {
		if err := checkRegistryUnauthenticated(ctx, regName); err != nil {
			return err
		}
		sp.Success(fmt.Sprintf("Remote registry %q implements docker registry API V2", regName))
		printer.Verbosef("Continuing without authentication, no user credentials provided")
		return nil
	}

	client := authn.NewClient(authn.WithCredentials(cred))

	// Ensure credentials are valid.
	registry, err := remote.NewRegistry(regName)
	if err != nil {
		return err
	}

	registry.Client = client
	if err = registry.Ping(ctx); err != nil {
		return err
	}

	sp.Success(fmt.Sprintf("Remote registry %q implements docker registry API V2", regName))
	printer.Verbosef("Proceeding as user %q", cred.Username)

	return nil
}

func checkRegistryUnauthenticated(ctx context.Context, regName string) error {
	url := fmt.Sprintf("https://%s/v2/", regName)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusUnauthorized:
		// We are just checking if the V2 endpoint exists. Do not care about authorization/authentication.
		return nil
	default:
		return fmt.Errorf("unable to check remote registry %q: %q", url, resp.Status)
	}
}
