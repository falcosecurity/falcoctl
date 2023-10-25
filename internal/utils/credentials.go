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

package utils

import (
	"bufio"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/falcosecurity/falcoctl/pkg/output"
)

// GetCredentials is used to retrieve username and password from standard input.
func GetCredentials(p *output.Printer) (username, password string, err error) {
	reader := bufio.NewReader(os.Stdin)

	p.DefaultText.Print(p.FormatTitleAsLoggerInfo("Enter username:"))
	username, err = reader.ReadString('\n')
	if err != nil {
		return "", "", err
	}

	p.Logger.Info("Enter password: ")
	bytePassword, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return "", "", err
	}

	password = string(bytePassword)
	return strings.TrimSpace(username), strings.TrimSpace(password), nil
}
