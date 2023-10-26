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

package basic

import (
	"context"
	"fmt"

	credentials "github.com/oras-project/oras-credentials-go"
	"github.com/spf13/cobra"

	"github.com/falcosecurity/falcoctl/internal/config"
	"github.com/falcosecurity/falcoctl/internal/login/basic"
	"github.com/falcosecurity/falcoctl/internal/utils"
	"github.com/falcosecurity/falcoctl/pkg/oci/authn"
	"github.com/falcosecurity/falcoctl/pkg/options"
)

type loginOptions struct {
	*options.Common
}

// NewBasicCmd returns the basic command.
func NewBasicCmd(ctx context.Context, opt *options.Common) *cobra.Command {
	o := loginOptions{
		Common: opt,
	}

	cmd := &cobra.Command{
		Use:                   "basic [hostname]",
		DisableFlagsInUseLine: true,
		Short:                 "Login to an OCI registry",
		Long:                  "Login to an OCI registry to push and pull artifacts",
		Args:                  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return o.RunBasic(ctx, args)
		},
	}

	return cmd
}

// RunBasic executes the business logic for the basic command.
func (o *loginOptions) RunBasic(ctx context.Context, args []string) error {
	reg := args[0]
	logger := o.Printer.Logger
	user, token, err := utils.GetCredentials(o.Printer)
	if err != nil {
		return err
	}

	// create empty client
	client := authn.NewClient()

	// create credential store
	credentialStore, err := credentials.NewStore(config.RegistryCredentialConfPath(), credentials.StoreOptions{
		AllowPlaintextPut: true,
	})
	if err != nil {
		return fmt.Errorf("unable to create new store: %w", err)
	}

	if err := basic.Login(ctx, client, credentialStore, reg, user, token); err != nil {
		return err
	}
	logger.Debug("Credentials added", logger.Args("credential store", config.RegistryCredentialConfPath()))
	logger.Info("Login succeeded", logger.Args("registry", reg, "user", user))

	return nil
}
