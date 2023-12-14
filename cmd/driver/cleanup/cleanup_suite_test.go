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

package drivercleanup_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
	"github.com/spf13/cobra"

	"github.com/falcosecurity/falcoctl/cmd"
	commonoptions "github.com/falcosecurity/falcoctl/pkg/options"
	testutils "github.com/falcosecurity/falcoctl/pkg/test"
)

var (
	ctx        = context.Background()
	output     = gbytes.NewBuffer()
	rootCmd    *cobra.Command
	opt        *commonoptions.Common
	configFile string
	err        error
	args       []string
)

func TestCleanup(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Cleanup Suite")
}

var _ = BeforeSuite(func() {

	// Create and configure the common options.
	opt = commonoptions.NewOptions()
	opt.Initialize(commonoptions.WithWriter(output))

	// Create temporary directory used to save the configuration file.
	configFile, err = testutils.CreateEmptyFile("falcoctl.yaml")
	Expect(err).Should(Succeed())
})

var _ = AfterSuite(func() {
	configDir := filepath.Dir(configFile)
	Expect(os.RemoveAll(configDir)).Should(Succeed())
})

func executeRoot(args []string) error {
	rootCmd.SetArgs(args)
	rootCmd.SetOut(output)
	return cmd.Execute(rootCmd, opt)
}
