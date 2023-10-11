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

package authn

import (
	"context"

	credentials "github.com/oras-project/oras-credentials-go"
	"oras.land/oras-go/v2/registry/remote/auth"

	"github.com/falcosecurity/falcoctl/internal/login"
)

// AutoLoginHandler performs registry logins automatically exactly once.
type AutoLoginHandler struct {
	client         *auth.Client
	autoLoginCache map[string]bool
	credStore      credentials.Store
}

// NewAutoLoginHandler creates a new AutoLoginHandler.
func NewAutoLoginHandler(credStore credentials.Store) *AutoLoginHandler {
	return &AutoLoginHandler{
		client:         NewClient(),
		autoLoginCache: make(map[string]bool),
		credStore:      credStore,
	}
}

// Login logs into the specified registry and stores the credentials in a local store.
func (a *AutoLoginHandler) Login(ctx context.Context, reg string) error {
	// only login if we did not already login for this registry
	if _, exists := a.autoLoginCache[reg]; !exists {
		return login.PerformAuthsFromConfigWithMap(ctx, a.client, a.credStore, map[string]bool{reg: true})
	}
	return nil
}
