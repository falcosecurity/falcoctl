// Copyright 2023 The Falco Authors
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

package oauth

import (
	"context"
	"fmt"

	"golang.org/x/oauth2/clientcredentials"

	"github.com/falcosecurity/falcoctl/internal/config"
)

// Login checks if passed oauth credentials are correct and stores them.
func Login(ctx context.Context, reg string, creds *clientcredentials.Config) error {
	// Check that we can retrieve token using the passed credentials.
	_, err := creds.Token(ctx)
	if err != nil {
		return fmt.Errorf("wrong client credentials, unable to retrieve token: %w", err)
	}

	// Save client credentials to file.
	if err = config.WriteClientCredentials(reg, creds); err != nil {
		return fmt.Errorf("unable to save token: %w", err)
	}

	return nil
}
