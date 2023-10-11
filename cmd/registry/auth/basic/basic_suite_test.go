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

package basic_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/distribution/distribution/v3/configuration"
	_ "github.com/distribution/distribution/v3/registry/storage/driver/inmemory"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/bcrypt"

	"github.com/falcosecurity/falcoctl/cmd"
	commonoptions "github.com/falcosecurity/falcoctl/pkg/options"
	testutils "github.com/falcosecurity/falcoctl/pkg/test"
)

//nolint:unused // false positive
var (
	registry      string
	registryBasic string
	ctx           = context.Background()
	output        = gbytes.NewBuffer()
	rootCmd       *cobra.Command
	opt           *commonoptions.Common
	port          int
	portBasic     int
	configFile    string
	err           error
	args          []string
)

func TestBasic(t *testing.T) {
	var err error
	RegisterFailHandler(Fail)
	port, err = testutils.FreePort()
	Expect(err).ToNot(HaveOccurred())
	portBasic, err = testutils.FreePort()
	Expect(err).ToNot(HaveOccurred())
	registry = fmt.Sprintf("localhost:%d", port)
	registryBasic = fmt.Sprintf("localhost:%d", portBasic)
	RunSpecs(t, "Auth Basic Suite")
}

var _ = BeforeSuite(func() {
	config := &configuration.Configuration{}
	config.HTTP.Addr = fmt.Sprintf("localhost:%d", port)

	testHtpasswdFileBasename := "authtest.htpasswd"
	testUsername, testPassword := "username", "password"

	pwBytes, err := bcrypt.GenerateFromPassword([]byte(testPassword), bcrypt.DefaultCost)
	Expect(err).To(BeNil())

	htpasswdPath := filepath.Join(GinkgoT().TempDir(), testHtpasswdFileBasename)
	err = os.WriteFile(htpasswdPath, []byte(fmt.Sprintf("%s:%s\n", testUsername, string(pwBytes))), 0o644)
	Expect(err).To(BeNil())

	tlsConfig, err := testutils.BuildRegistryTLSConfig(GinkgoT().TempDir(), []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"})
	Expect(err).To(BeNil())

	configBasic := &configuration.Configuration{}
	configBasic.HTTP.Addr = fmt.Sprintf("localhost:%d", portBasic)
	configBasic.Auth = configuration.Auth{
		"htpasswd": configuration.Parameters{
			"realm": "localhost",
			"path":  htpasswdPath,
		},
	}
	configBasic.HTTP.DrainTimeout = time.Duration(10) * time.Second
	configBasic.HTTP.TLS.CipherSuites = tlsConfig.CipherSuites
	configBasic.HTTP.TLS.Certificate = tlsConfig.CertificatePath
	configBasic.HTTP.TLS.Key = tlsConfig.PrivateKeyPath

	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{
		InsecureSkipVerify: true,
	}

	// Create and configure the common options.
	opt = commonoptions.NewOptions()
	opt.Initialize(commonoptions.WithWriter(output))
	opt.Printer.DisableStylingf()

	// Start the local registry.
	go func() {
		err := testutils.StartRegistry(context.Background(), config)
		Expect(err).ToNot(BeNil())
	}()

	// Start the local registry with basic authentication.
	go func() {
		err := testutils.StartRegistry(context.Background(), configBasic)
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
	return cmd.Execute(rootCmd, opt.Printer)
}
