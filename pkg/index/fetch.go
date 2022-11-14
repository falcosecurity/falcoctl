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
	"context"
	"fmt"
	"io"
	"net/http"

	"gopkg.in/yaml.v3"
)

// FetchIndex retrieves a remote index using its URL.
func FetchIndex(ctx context.Context, url string) (*Index, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("cannot fetch index: %w", err)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cannot fetch index: %w", err)
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
