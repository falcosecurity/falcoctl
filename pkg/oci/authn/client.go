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

	credentials "github.com/oras-project/oras-credentials-go"
	"oras.land/oras-go/v2/registry/remote/auth"
)

const (
	falcoctlUserAgent = "falcoctl"
)

// Options used for the HTTP client that can authenticate with auth.Credentials or via OAuth2.0 Options Credentials flow.
type Options struct {
	Ctx                   context.Context
	CredentialsFuncsCache map[string]func(context.Context, string) (auth.Credential, error)
	CredentialsFuncs      []func(context.Context, string) (auth.Credential, error)
	AutoLoginHandler      *AutoLoginHandler
}

// NewClient creates a new authenticated client to interact with a remote registry.
func NewClient(options ...func(*Options)) *auth.Client {
	opt := &Options{
		CredentialsFuncsCache: make(map[string]func(context.Context, string) (auth.Credential, error)),
	}

	for _, o := range options {
		o(opt)
	}

	authClient := auth.Client{
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
		Credential: func(ctx context.Context, reg string) (auth.Credential, error) {
			// try cred func from cache first
			credFunc, exists := opt.CredentialsFuncsCache[reg]
			if exists {
				return credFunc(ctx, reg)
			}

			// if auto login is on check if we tried logging in to registry
			if opt.AutoLoginHandler != nil {
				if err := opt.AutoLoginHandler.Login(ctx, reg); err != nil {
					return auth.EmptyCredential, err
				}
			}

			// if we did not cache the correct cred function yet search available ones
			for _, credFunc := range opt.CredentialsFuncs {
				cred, err := credFunc(ctx, reg)
				if err != nil {
					return auth.EmptyCredential, err
				}

				if cred != auth.EmptyCredential {
					// remember cred function for this reg for next time
					opt.CredentialsFuncsCache[reg] = credFunc
					return cred, nil
				}
			}
			// remember empty cred func for registries we dont have creds for
			opt.CredentialsFuncsCache[reg] = EmptyCredentialFunc
			return auth.EmptyCredential, nil
		},
	}

	authClient.SetUserAgent(falcoctlUserAgent)

	return &authClient
}

// WithAutoLogin enables the clients auto login feature.
func WithAutoLogin(handler *AutoLoginHandler) func(c *Options) {
	return func(c *Options) {
		c.AutoLoginHandler = handler
	}
}

// EmptyCredentialFunc provides empty auth credentials.
func EmptyCredentialFunc(context.Context, string) (auth.Credential, error) {
	return auth.EmptyCredential, nil
}

// WithOAuthCredentials adds the oauth credential store as credential source to the client.
func WithOAuthCredentials() func(c *Options) {
	return func(c *Options) {
		oauthStore := NewOauthClientCredentialsStore()
		c.CredentialsFuncs = append(c.CredentialsFuncs, oauthStore.Credential)
	}
}

// WithGkeCredentials adds the gke source to the client.
func WithGkeCredentials() func(c *Options) {
	return func(c *Options) {
		gkeStore := NewGkeClientCredentialsStore()
		c.CredentialsFuncs = append(c.CredentialsFuncs, gkeStore.Credential)
	}
}

// WithCredentials adds a static credential function to the client.
func WithCredentials(cred *auth.Credential) func(c *Options) {
	return func(c *Options) {
		c.CredentialsFuncs = append(c.CredentialsFuncs, func(context.Context, string) (auth.Credential, error) {
			return *cred, nil
		})
	}
}

// WithStore adds the basic auth credential store as credential source to the client.
func WithStore(store credentials.Store) func(c *Options) {
	return func(c *Options) {
		c.CredentialsFuncs = append(c.CredentialsFuncs, credentials.Credential(store))
	}
}
