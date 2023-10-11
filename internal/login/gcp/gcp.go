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

package gcp

import (
	"context"
	"fmt"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/falcosecurity/falcoctl/pkg/oci/registry"
)

// Login checks if passed gcp credentials are correct.
func Login(ctx context.Context, reg string) error {
	// Check that we can find a valid token source using GCE or ApplicationDefault.
	ts, err := google.DefaultTokenSource(ctx)
	if err != nil {
		return fmt.Errorf("wrong GCP token source, unable to find a valid source: %w", err)
	}

	// Check that we can retrieve token.
	_, err = ts.Token()
	if err != nil {
		return fmt.Errorf("wrong GCP credentials, unable to retrieve token: %w", err)
	}

	// Check connection to the registry
	client := oauth2.NewClient(ctx, ts)

	r, err := registry.NewRegistry(reg, registry.WithClient(client))
	if err != nil {
		return err
	}

	if err := r.CheckConnection(ctx); err != nil {
		return fmt.Errorf("unable to connect to registry %q: %w", reg, err)
	}

	return nil
}
