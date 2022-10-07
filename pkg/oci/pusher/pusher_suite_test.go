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

package pusher_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/distribution/distribution/v3/configuration"
	"github.com/distribution/distribution/v3/registry"
	_ "github.com/distribution/distribution/v3/registry/storage/driver/inmemory"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/registry/remote"

	"github.com/falcosecurity/falcoctl/pkg/oci"
)

var (
	localRegistryHost   string
	localRegistry       *remote.Registry
	testRuleTarball     = "./testdata/rules.tar.gz"
	testPluginTarball   = "./testdata/plugin.tar.gz"
	testPluginPlatform1 = "linux/amd64"
	testPluginPlatform2 = "windows/amd64"
	testPluginPlatform3 = "linux/aarch64"
	ctx                 = context.Background()
)

func TestPusher(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Pusher Suite")
}

var _ = BeforeSuite(func() {
	config := &configuration.Configuration{}
	port, err := freePort()
	Expect(err).ToNot(HaveOccurred())
	localRegistryHost = fmt.Sprintf("localhost:%d", port)
	config.HTTP.Addr = fmt.Sprintf(":%d", port)
	config.HTTP.DrainTimeout = time.Duration(10) * time.Second
	config.Storage = map[string]configuration.Parameters{"inmemory": map[string]interface{}{}}
	dockerRegistry, err := registry.NewRegistry(ctx, config)
	Expect(err).ToNot(HaveOccurred())

	// Create the oras registry.
	localRegistry, err = remote.NewRegistry(localRegistryHost)
	localRegistry.PlainHTTP = true
	Expect(err).ToNot(HaveOccurred())

	// Start the local registry.
	go func() {
		err := dockerRegistry.ListenAndServe()
		Expect(err).ToNot(BeNil())
	}()
})

// freePort get a free port on the system by listening in a socket,
// checking the bound port number and then closing the socket.
func freePort() (int, error) {
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

func manifestFromReader(descReader io.Reader) (*v1.Manifest, error) {
	var manifest v1.Manifest
	descBytes, err := io.ReadAll(descReader)
	if err != nil {
		return nil, fmt.Errorf("unable to read bytes from descriptor: %w", err)
	}

	if err = json.Unmarshal(descBytes, &manifest); err != nil {
		return nil, fmt.Errorf("unable to unmarshal manifest: %w", err)
	}

	return &manifest, nil
}

func imageIndexFromReader(descReader io.Reader) (*v1.Index, error) {
	var index v1.Index
	descBytes, err := io.ReadAll(descReader)
	if err != nil {
		return nil, fmt.Errorf("unable to read bytes from descriptor: %w", err)
	}

	if err = json.Unmarshal(descBytes, &index); err != nil {
		return nil, fmt.Errorf("unable to unmarshal manifest: %w", err)
	}

	return &index, nil
}

func dependenciesFromReader(descReader io.Reader) (*oci.ArtifactConfig, error) {
	var dep oci.ArtifactConfig
	descBytes, err := io.ReadAll(descReader)
	if err != nil {
		if err != nil {
			return nil, fmt.Errorf("unable to read bytes from descriptor: %w", err)
		}
	}
	if err = json.Unmarshal(descBytes, &dep); err != nil {
		return nil, fmt.Errorf("unable to unmarshal dependencies: %w", err)
	}

	return &dep, nil
}
