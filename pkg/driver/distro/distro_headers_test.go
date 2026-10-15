// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The Falco Authors
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

package driverdistro

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
	"github.com/pterm/pterm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	drivertype "github.com/falcosecurity/falcoctl/pkg/driver/type"
	"github.com/falcosecurity/falcoctl/pkg/output"
)

const (
	testHeaderKey   = "X-Test"
	testHeaderValue = "ok"
)

// TestDownloadHTTPHeaders drives Download against a local server and reports
// which headers the server actually received.
func TestDownloadHTTPHeaders(t *testing.T) {
	tests := []struct {
		name        string
		httpHeaders string
		want        map[string]string
	}{
		{
			name:        "no headers",
			httpHeaders: "",
			want:        map[string]string{},
		},
		{
			name:        "one well formed header",
			httpHeaders: testHeaderKey + ":" + testHeaderValue,
			want:        map[string]string{testHeaderKey: testHeaderValue},
		},
		{
			name:        "value containing a colon is kept whole",
			httpHeaders: "X-Fwd:host.example.com:8443",
			want:        map[string]string{"X-Fwd": "host.example.com:8443"},
		},
		{
			name:        "header without a separator is skipped",
			httpHeaders: "Proxy-Authenticate",
			want:        map[string]string{},
		},
		{
			name:        "the well formed header of a mixed pair still arrives",
			httpHeaders: testHeaderKey + ":" + testHeaderValue + ",Proxy-Authenticate",
			want:        map[string]string{testHeaderKey: testHeaderValue},
		},
		{
			name:        "surrounding spaces are trimmed",
			httpHeaders: testHeaderKey + ": " + testHeaderValue + " ",
			want:        map[string]string{testHeaderKey: testHeaderValue},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got http.Header
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got = r.Header.Clone()
				_, _ = io.WriteString(w, "driver")
			}))
			defer server.Close()

			t.Setenv("HOME", t.TempDir())

			driverType, err := drivertype.Parse(drivertype.TypeKmod)
			require.NoError(t, err)
			kr := kernelrelease.FromString("6.8.0-45-generic")
			kr.Architecture = kernelrelease.ArchitectureAmd64
			printer := output.NewPrinter(pterm.LogLevelInfo, pterm.LogFormatterJSON, io.Discard)

			_, err = Download(context.Background(), &generic{}, printer, kr,
				"falco_headers_test", driverType, "7.0.0+driver",
				[]string{server.URL + "/"}, tt.httpHeaders)
			require.NoError(t, err)

			for key, want := range tt.want {
				assert.Equal(t, want, got.Get(key), "header %q", key)
			}
			if _, ok := tt.want["Proxy-Authenticate"]; !ok {
				assert.Empty(t, got.Get("Proxy-Authenticate"))
			}
		})
	}
}

// TestDownloadMalformedHeaderIsNotLogged checks that a malformed token is
// skipped without its contents reaching the log. The usual way to get here is
// a forgotten colon in an Authorization header, so the skipped token is the
// credential itself.
func TestDownloadMalformedHeaderIsNotLogged(t *testing.T) {
	const token = "bqN7wKxZ4mVtLcRe9sYu3PdF"

	var got http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		_, _ = io.WriteString(w, "driver")
	}))
	defer server.Close()

	t.Setenv("HOME", t.TempDir())

	driverType, err := drivertype.Parse(drivertype.TypeKmod)
	require.NoError(t, err)
	kr := kernelrelease.FromString("6.8.0-45-generic")
	kr.Architecture = kernelrelease.ArchitectureAmd64

	var logs bytes.Buffer
	printer := output.NewPrinter(pterm.LogLevelInfo, pterm.LogFormatterJSON, &logs)

	_, err = Download(context.Background(), &generic{}, printer, kr,
		"falco_headers_leak_test", driverType, "7.0.0+driver",
		[]string{server.URL + "/"}, "Authorization Bearer "+token)
	require.NoError(t, err)

	// Without this the rest of the test passes whenever the branch is not
	// reached at all.
	require.Contains(t, logs.String(), "Skipping malformed http header",
		"the malformed header branch did not run, so the assertions below prove nothing")
	assert.Contains(t, logs.String(), "position")

	// A prefix of a bearer token is still a bearer token, so check the short
	// ones too.
	for _, n := range []int{len(token), 12, 8} {
		assert.NotContains(t, logs.String(), token[:n],
			"the first %d characters of the token reached the log", n)
	}
	assert.NotContains(t, logs.String(), "Authorization")
	assert.Empty(t, got.Get("Authorization"))
}

// TestDownloadWellFormedAuthorizationIsSent is the companion to the test
// above: a header that does parse must still be delivered, otherwise the
// no-leak assertion could be satisfied by dropping every header.
func TestDownloadWellFormedAuthorizationIsSent(t *testing.T) {
	const token = "bqN7wKxZ4mVtLcRe9sYu3PdF"

	var got http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		_, _ = io.WriteString(w, "driver")
	}))
	defer server.Close()

	t.Setenv("HOME", t.TempDir())

	driverType, err := drivertype.Parse(drivertype.TypeKmod)
	require.NoError(t, err)
	kr := kernelrelease.FromString("6.8.0-45-generic")
	kr.Architecture = kernelrelease.ArchitectureAmd64

	var logs bytes.Buffer
	printer := output.NewPrinter(pterm.LogLevelInfo, pterm.LogFormatterJSON, &logs)

	_, err = Download(context.Background(), &generic{}, printer, kr,
		"falco_headers_ok_test", driverType, "7.0.0+driver",
		[]string{server.URL + "/"}, "Authorization:Bearer "+token)
	require.NoError(t, err)

	assert.Equal(t, "Bearer "+token, got.Get("Authorization"))
	assert.NotContains(t, logs.String(), token[:8])
	assert.False(t, strings.Contains(logs.String(), "Skipping malformed http header"))
}
