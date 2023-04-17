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

package test

import (
	"context"
	"net"

	"github.com/distribution/distribution/v3/configuration"
	"github.com/distribution/distribution/v3/registry"
)

// FreePort get a free port on the system by listening in a socket,
// checking the bound port number and then closing the socket.
func FreePort() (int, error) {
	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	if err != nil {
		return 0, err
	}

	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// StartRegistry starts a new OCI registry and returns it's address.
func StartRegistry(ctx context.Context, cfg *configuration.Configuration) error {
	if cfg.Storage == nil {
		cfg.Storage = map[string]configuration.Parameters{"inmemory": map[string]interface{}{}}
	}

	// Create registry.
	reg, err := registry.NewRegistry(ctx, cfg)
	if err != nil {
		return err
	}

	// Start serving in goroutine and listen for stop signal in main thread
	return reg.ListenAndServe()
}
