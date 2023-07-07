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

package fetch

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/falcosecurity/falcoctl/pkg/index/config"
	"github.com/falcosecurity/falcoctl/pkg/index/fetch/gcs"
	"github.com/falcosecurity/falcoctl/pkg/index/fetch/http"
	"github.com/falcosecurity/falcoctl/pkg/index/index"
)

// Func is a prototype for fetching indices for a specific index backend.
type Func func(context.Context, *config.Entry) ([]byte, error)

// Fetcher can fetch indices from various storage backends.
type Fetcher struct {
	fetchFuncs            map[string]Func
	schemeDefaultBackends map[string]string
}

// NewFetcher creates a new index fetcher.
func NewFetcher() *Fetcher {
	return &Fetcher{
		fetchFuncs: map[string]Func{
			// default to HTTP
			"": http.Fetch,
			// for convenient UX we map the HTTP backend to both HTTP and HTTPS
			"http":  http.Fetch,
			"https": http.Fetch,
			"gcs":   gcs.Fetch,
		},
		schemeDefaultBackends: map[string]string{
			"http":  "http",
			"https": "https",
			"gs":    "gcs",
		},
	}
}

func (f *Fetcher) get(backend string) (Func, error) {
	fetchFunc, ok := f.fetchFuncs[strings.ToLower(backend)]
	if !ok {
		return nil, fmt.Errorf("unsupported index backend type: %s", backend)
	}
	return fetchFunc, nil
}

// Fetch retrieves a remote index.
func (f *Fetcher) Fetch(ctx context.Context, conf *config.Entry) (*index.Index, error) {
	// if we don't have an explicit backend
	// we try to guess based on the URI scheme
	if conf.Backend == "" {
		indexURL, err := url.Parse(conf.URL)
		if err != nil {
			return nil, fmt.Errorf("unable to parse index url: %w", err)
		}
		if mappedBackend, ok := f.schemeDefaultBackends[strings.ToLower(indexURL.Scheme)]; ok {
			conf.Backend = mappedBackend
		}
	}

	fetcher, err := f.get(conf.Backend)
	if err != nil {
		return nil, err
	}

	bytes, err := fetcher(ctx, conf)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch index: %w", err)
	}

	i := index.New(conf.Name)
	err = i.ReadBytes(bytes)
	if err != nil {
		return nil, err
	}

	return i, nil
}
