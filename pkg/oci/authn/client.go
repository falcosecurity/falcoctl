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

package authn

import (
	"context"
	"net"
	"net/http"
	"time"

	"oras.land/oras-go/v2/registry/remote/auth"
)

const (
	falcoctlUserAgent = "falcoctl"
)

// NewClient creates a new authenticated client to interact with a remote registry.
func NewClient(cred auth.Credential) *auth.Client {
	client := &auth.Client{
		Client: &http.Client{
			Transport: &http.Transport{
				Proxy: http.ProxyFromEnvironment,
				DialContext: (&net.Dialer{
					Timeout:   30 * time.Second,
					KeepAlive: 30 * time.Second,
				}).DialContext,
				ForceAttemptHTTP2:     true,
				MaxIdleConns:          100,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
				// TODO(loresuso, alacuku): tls config.
			},
		},
		Cache: auth.NewCache(),
		Credential: func(ctx context.Context, registry string) (auth.Credential, error) {
			return cred, nil
		},
	}

	client.SetUserAgent(falcoctlUserAgent)

	return client
}

// Login to remote registry.
// For now, only support login with token.
func Login(hostname, user, token string) error {
	store, err := NewStore([]string{}...)
	if err != nil {
		return err
	}

	cred := auth.Credential{
		Username: user,
		Password: token,
	}

	if err := store.Store(hostname, cred); err != nil {
		return err
	}

	return nil
}

// Logout from remote registry.
func Logout(hostname string) error {
	store, err := NewStore([]string{}...)
	if err != nil {
		return err
	}

	err = store.Erase(hostname)
	if err != nil {
		return err
	}

	return nil
}
