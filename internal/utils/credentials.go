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

// WriteClientCredentials writes client credentials to config file.
func WriteClientCredentials(cred *clientcredentials.Config) error {
	data, err := json.Marshal(cred)
	if err != nil {
		return fmt.Errorf("unanle to marshal %+v", cred)
	}

	if err = os.WriteFile(config.ClientCredentialsFile, data, 0o600); err != nil {
		return fmt.Errorf("unable to write to %s: %w", config.ClientCredentialsFile, err)
	}

	return nil
}

// ReadClientCredentials reads client credentials from config file.
func ReadClientCredentials() (*clientcredentials.Config, error) {
	data, err := os.ReadFile(config.ClientCredentialsFile)
	if err != nil {
		return nil, fmt.Errorf("unable to read from %s: %w", config.ClientCredentialsFile, err)
	}

	var cred clientcredentials.Config
	err = json.Unmarshal(data, &cred)
	if err != nil {
		return nil, fmt.Errorf("unable to unmarshal client credentials: %w", err)
	}

	return &cred, nil
}
