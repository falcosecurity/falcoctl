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
	username string
	password string
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
		SilenceErrors:         true,
		SilenceUsage:          true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return o.RunBasic(ctx, args)
		},
	}

	cmd.Flags().StringVarP(&o.username, "username", "u", "", "username of the basic authentication to the OCI registry")
	cmd.Flags().StringVarP(&o.password, "password", "p", "", "password of the basic authentication to the OCI registry")

	return cmd
}

// RunBasic executes the business logic for the basic command.
func (o *loginOptions) RunBasic(ctx context.Context, args []string) error {
	var reg string
	if len(args) > 0 {
		reg = args[0]
	}

	if err := o.ensureCredentials(); err != nil {
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

	if err := basic.Login(ctx, client, credentialStore, reg, o.username, o.password); err != nil {
		return err
	}
	o.Printer.Verbosef("credentials added to credential store")
	o.Printer.Success.Println("Login succeeded")

	return nil
}

func (o *loginOptions) ensureCredentials() error {
	if o.username == "" || o.password == "" {
		var err error
		if o.username, o.password, err = utils.GetCredentials(o.Printer); err != nil {
			return err
		}
	}

	return nil
}
