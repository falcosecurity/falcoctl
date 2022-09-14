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

package index

import (
	"fmt"
	"io"
	"net/http"

	"gopkg.in/yaml.v3"
)

// GetIndex retrieves a remote index using its URL.
func FetchIndex(url string) (*Index, error) { // IndexByUrl !!
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}

	// Check server response
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("cannot download index, bad response status: %s", resp.Status)
	}
	defer resp.Body.Close()

	bytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("cannot read bytes from response body: %w", err)
	}

	var index Index
	if err := yaml.Unmarshal(bytes, &index.Entries); err != nil {
		return nil, fmt.Errorf("cannot unmarshal index: %w", err)
	}

	return &index, nil
}
