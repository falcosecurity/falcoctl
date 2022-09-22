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

	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"

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

// CheckRegistryConnection checks whether the registry implement Docker Registry API V2 or
// OCI Distribution Specification. It also checks authentication if credentials are not empty.
func CheckRegistryConnection(ctx context.Context, cred *auth.Credential, regName string, printer *output.Printer) error {
	sp, _ := printer.Spinner.Start(fmt.Sprintf("Checking connection to remote registry %q", regName))

	if reflect.DeepEqual(*cred, auth.EmptyCredential) {
		if err := checkRegistryUnauthenticated(ctx, regName); err != nil {
			return err
		}
		sp.Success(fmt.Sprintf("Remote registry %q implements docker registry API V2", regName))
		printer.Verbosef("Continuing without authentication, no user credentials provided")
		return nil
	}

	client := authn.NewClient(*cred)

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
