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
	"strings"

	"github.com/falcosecurity/falcoctl/pkg/index/fetch/http"
	"gopkg.in/yaml.v3"
)

// FetchFunc is a prototype for fetching indices for a specific index backend.
type FetchFunc func(context.Context, string) ([]byte, error)

// Fetcher can fetch indices from various storage backends.
type Fetcher struct {
	fetchFuncs map[string]FetchFunc
}

// NewFetcher creates a new index fetcher.
func NewFetcher() *Fetcher {
	return &Fetcher{
		fetchFuncs: map[string]FetchFunc{
			"":      http.Fetch,
			"http":  http.Fetch,
			"https": http.Fetch,
		},
	}
}

func (f *Fetcher) get(backend string) (FetchFunc, error) {
	fetchFunc, ok := f.fetchFuncs[strings.ToLower(backend)]
	if !ok {
		return nil, fmt.Errorf("unsupported index backend type: %s", backend)
	}
	return fetchFunc, nil
}

// Fetch retrieves a remote index using its URL.
func (f *Fetcher) Fetch(ctx context.Context, backend, url, name string) (*Index, error) {
	fetcher, err := f.get(backend)
	if err != nil {
		return nil, err
	}

	bytes, err := fetcher(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch index: %w", err)
	}

	i := New(name)
	if err := yaml.Unmarshal(bytes, &i.Entries); err != nil {
		return nil, fmt.Errorf("cannot unmarshal index: %w", err)
	}

	i.entryByName = make(map[string]*Entry, len(i.Entries))
	for _, e := range i.Entries {
		if _, ok := i.entryByName[e.Name]; ok {
			return nil, fmt.Errorf("duplicate entry found: %s", e.Name)
		}
		i.entryByName[e.Name] = e
	}

	return i, nil
}
