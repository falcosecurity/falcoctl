// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 The Falco Authors
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

package file

import (
	"context"
	"fmt"
	pkgurl "net/url"
	"os"

	"github.com/falcosecurity/falcoctl/pkg/index/config"
)

// Fetch fetches the raw index file from the local file system.
func Fetch(_ context.Context, conf *config.Entry) ([]byte, error) {
	// Expect URL to be file:///some/directory/filename.yaml
	url, err := pkgurl.Parse(conf.URL)
	if err != nil {
		return nil, fmt.Errorf("cannot parse URL: %w", err)
	}

	data, err := os.ReadFile(url.Path)
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}

	return data, nil
}
