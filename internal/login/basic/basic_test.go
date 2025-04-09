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

package basic

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"oras.land/oras-go/v2/registry/remote/auth"
)

// mockCredentialStore is a mock implementation of the credentials.Store interface
type mockCredentialStore struct {
	putErr error
}

func (m *mockCredentialStore) Put(ctx context.Context, host string, cred auth.Credential) error {
	return m.putErr
}

func (m *mockCredentialStore) Delete(ctx context.Context, host string) error {
	return nil
}

func (m *mockCredentialStore) Get(ctx context.Context, host string) (auth.Credential, error) {
	return auth.EmptyCredential, nil
}

func TestLogin(t *testing.T) {
	// Create a test server that simulates a registry
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})

	// Create HTTP server for insecure tests
	httpServer := httptest.NewServer(handler)
	defer httpServer.Close()

	// Create HTTPS server for secure tests
	httpsServer := httptest.NewTLSServer(handler)
	defer httpsServer.Close()

	// Configure HTTP client to trust the test server's certificate
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{
		InsecureSkipVerify: true,
	}

	tests := []struct {
		name           string
		registry       string
		username       string
		password       string
		insecure       bool
		putErr         error
		expectedErr    error
		expectedErrMsg string
	}{
		{
			name:           "successful login with secure connection",
			registry:       httpsServer.URL[8:], // Remove "https://" prefix
			username:       "testuser",
			password:       "testpass",
			insecure:       false,
			putErr:         nil,
			expectedErr:    nil,
			expectedErrMsg: "",
		},
		{
			name:           "successful login with insecure connection",
			registry:       httpServer.URL[7:], // Remove "http://" prefix
			username:       "testuser",
			password:       "testpass",
			insecure:       true,
			putErr:         nil,
			expectedErr:    nil,
			expectedErrMsg: "",
		},
		{
			name:           "failed credential store put",
			registry:       httpsServer.URL[8:], // Remove "https://" prefix
			username:       "testuser",
			password:       "testpass",
			insecure:       false,
			putErr:         errors.New("failed to store credentials"),
			expectedErr:    errors.New("unable to save credentials in credential store: failed to store credentials"),
			expectedErrMsg: "unable to save credentials in credential store: failed to store credentials",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock credential store
			mockStore := &mockCredentialStore{
				putErr: tt.putErr,
			}

			// Create auth client
			client := &auth.Client{}

			// Create context
			ctx := context.Background()

			// Call Login
			err := Login(ctx, client, mockStore, tt.registry, tt.username, tt.password, tt.insecure)

			// Check error
			if tt.expectedErr != nil {
				require.Error(t, err)
				assert.Equal(t, tt.expectedErrMsg, err.Error())
			} else {
				require.NoError(t, err)
			}
		})
	}
} 
