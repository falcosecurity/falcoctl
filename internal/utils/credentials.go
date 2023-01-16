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
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/oauth2/clientcredentials"
	"golang.org/x/term"

	"github.com/falcosecurity/falcoctl/internal/config"
	"github.com/falcosecurity/falcoctl/pkg/output"
)

// GetCredentials is used to retrieve username and password from standard input.
func GetCredentials(p *output.Printer) (username, password string, err error) {
	reader := bufio.NewReader(os.Stdin)

	p.DefaultText.Print("Username: ")
	username, err = reader.ReadString('\n')
	if err != nil {
		return "", "", err
	}

	p.DefaultText.Print("Password: ")
	bytePassword, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return "", "", err
	}

	p.DefaultText.Println()

	password = string(bytePassword)
	return strings.TrimSpace(username), strings.TrimSpace(password), nil
}

// RegistryClientCredentials is used to store registry:clientCrendetials key value.
// This is done to be in accordance with the way Docker stores credentials, so that
// users will be able to store only one credential per registry.
type RegistryClientCredentials map[string]clientcredentials.Config

// WriteClientCredentials writes client credentials to config file.
func WriteClientCredentials(registry string, cred *clientcredentials.Config) error {
	creds, err := readClientCredentials()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}

	if creds == nil {
		creds = make(RegistryClientCredentials)
	}
	creds[registry] = *cred

	data, err := json.Marshal(creds)
	if err != nil {
		return fmt.Errorf("unable to marshal %+v", creds)
	}

	if err = os.WriteFile(config.ClientCredentialsFile, data, 0o600); err != nil {
		return fmt.Errorf("unable to write to %s: %w", config.ClientCredentialsFile, err)
	}

	return nil
}

// readClientCredentials reads client credentials from config file.
func readClientCredentials() (RegistryClientCredentials, error) {
	data, err := os.ReadFile(config.ClientCredentialsFile)
	if err != nil {
		return nil, fmt.Errorf("unable to read from %s: %w", config.ClientCredentialsFile, err)
	}

	var creds RegistryClientCredentials
	err = json.Unmarshal(data, &creds)
	if err != nil {
		return nil, fmt.Errorf("unable to unmarshal client credentials: %w", err)
	}

	return creds, nil
}

// ClientCredentials retrieves the client credentials for a specific registry.
func ClientCredentials(reg string) (*clientcredentials.Config, error) {
	regCreds, err := readClientCredentials()
	if err != nil && errors.Is(err, os.ErrNotExist) {
		// Legit, will proceed with empty creds
		return nil, nil
	}

	if err != nil {
		return nil, err
	}

	regCred, ok := regCreds[reg]
	if ok {
		return &regCred, nil
	}

	// Legit, will proceed with empty creds
	return nil, nil
}
