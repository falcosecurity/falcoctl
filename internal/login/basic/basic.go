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

package basic

import (
	"context"
	"fmt"

	credentials "github.com/oras-project/oras-credentials-go"
	"oras.land/oras-go/v2/registry/remote/auth"

	"github.com/falcosecurity/falcoctl/pkg/oci/registry"
)

// Login checks if passed credentials are correct and stores them.
func Login(ctx context.Context, client *auth.Client, credStore credentials.Store, reg, username, password string) error {
	cred := auth.Credential{
		Username: username,
		Password: password,
	}

	client.Credential = auth.StaticCredential(reg, cred)

	r, err := registry.NewRegistry(reg, registry.WithClient(client))
	if err != nil {
		return err
	}

	if err := r.CheckConnection(ctx); err != nil {
		return fmt.Errorf("unable to connect to registry %q: %w", reg, err)
	}

	err = credStore.Put(ctx, reg, cred)
	if err != nil {
		return fmt.Errorf("unable to save credentials in credential store: %w", err)
	}
	return nil
}
