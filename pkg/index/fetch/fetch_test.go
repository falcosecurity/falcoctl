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
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/falcosecurity/falcoctl/pkg/index/config"
)

func TestFetch(t *testing.T) {
	fetcher := NewFetcher()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("invalid request")
		}

		bytes, err := os.ReadFile("../testdata/index.yaml")
		if err != nil {
			t.Error(err)
		}

		if _, err := w.Write(bytes); err != nil {
			t.Error(err)
		}
	}))
	defer ts.Close()

	indexConf := &config.Entry{
		Name:    "falcosecurity",
		Backend: "http",
		URL:     ts.URL,
	}

	_, err := fetcher.Fetch(context.Background(), indexConf)
	if err != nil {
		t.Errorf("cannot fetch index")
	}
}
