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
// OCI Distribution Specification. It also checks authentication.
func CheckRegistryConnection(ctx context.Context, cred *auth.Credential, regName string, printer *output.Printer) error {
	sp, _ := printer.Spinner.Start(fmt.Sprintf("Checking connection to remote registry %q", regName))
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

	sp.Success(fmt.Sprintf("Remote registry %q is reachable", regName))

	return nil
}
