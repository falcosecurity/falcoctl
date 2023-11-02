// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2023 The Falco Authors
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

package oauth_test

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"testing"
	"time"

	"github.com/distribution/distribution/v3/configuration"
	_ "github.com/distribution/distribution/v3/registry/storage/driver/inmemory"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
	"github.com/spf13/cobra"
	"oras.land/oras-go/v2/registry/remote"

	"github.com/falcosecurity/falcoctl/cmd"
	commonoptions "github.com/falcosecurity/falcoctl/pkg/options"
	testutils "github.com/falcosecurity/falcoctl/pkg/test"
)

//nolint:unused // false positive
var (
	registry     string
	oauthServer  string
	oauthPort    int
	ctx          = context.Background()
	output       = gbytes.NewBuffer()
	rootCmd      *cobra.Command
	opt          *commonoptions.Common
	port         int
	orasRegistry *remote.Registry
	configFile   string
	err          error
	args         []string
)

func TestOAuth(t *testing.T) {
	var err error
	RegisterFailHandler(Fail)
	port, err = testutils.FreePort()
	Expect(err).ToNot(HaveOccurred())
	oauthPort, err = testutils.FreePort()
	Expect(err).ToNot(HaveOccurred())
	registry = fmt.Sprintf("localhost:%d", port)
	RunSpecs(t, "OAuth Suite")
}

var _ = BeforeSuite(func() {

	// Get the current user's home directory
	usr, err := user.Current()
	Expect(err).ToNot(HaveOccurred())

	// Construct the path for the .config directory
	configDir := filepath.Join(usr.HomeDir, ".config", "falcoctl")

	// Check if the directory already exists
	if _, err := os.Stat(configDir); os.IsNotExist(err) {
		// Directory doesn't exist, create it
		err := os.MkdirAll(configDir, 0o755)
		Expect(err).ToNot(HaveOccurred())
	}

	config := &configuration.Configuration{}
	config.HTTP.Addr = fmt.Sprintf("localhost:%d", port)
	// Create and configure the common options.
	opt = commonoptions.NewOptions()
	opt.Initialize(commonoptions.WithWriter(output))

	// Create the oras registry.
	orasRegistry, err = testutils.NewOrasRegistry(registry, true)
	Expect(err).ToNot(HaveOccurred())

	// Start the local registry.
	go func() {
		err := testutils.StartRegistry(context.Background(), config)
		Expect(err).ToNot(BeNil())
	}()

	// Check that the registry is up and accepting connections.
	Eventually(func(g Gomega) error {
		res, err := http.Get(fmt.Sprintf("http://%s", config.HTTP.Addr))
		g.Expect(err).ShouldNot(HaveOccurred())
		g.Expect(res.StatusCode).Should(Equal(http.StatusOK))
		return err
	}).WithTimeout(time.Second * 5).ShouldNot(HaveOccurred())

	go func() {
		err := testutils.StartOAuthServer(context.Background(), oauthPort)
		Expect(err).ToNot(BeNil())
	}()

	// Create temporary directory used to save the configuration file.
	configFile, err = testutils.CreateEmptyFile("falcoctl.yaml")
	Expect(err).Should(Succeed())
})

var _ = AfterSuite(func() {
	configDir := filepath.Dir(configFile)
	Expect(os.RemoveAll(configDir)).Should(Succeed())
})

//nolint:unused // false positive
func executeRoot(args []string) error {
	rootCmd.SetArgs(args)
	rootCmd.SetOut(output)
	return cmd.Execute(rootCmd, opt)
}
