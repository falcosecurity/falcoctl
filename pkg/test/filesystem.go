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

package test

import (
	"os"
	"path/filepath"
)

// CreateEmptyFile create a directory + file under /tmp.
func CreateEmptyFile(name string) (string, error) {
	// Create temporary directory used to save the configuration file.
	configDir, err := os.MkdirTemp("", "falcoctl-tests")
	if err != nil {
		return "", err
	}

	configFile := filepath.Join(configDir, name)
	_, err = os.OpenFile(filepath.Clean(configFile), os.O_RDONLY|os.O_CREATE, 0o600)
	if err != nil {
		return "", err
	}

	return configFile, nil
}
