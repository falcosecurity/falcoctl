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

package login

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	"oras.land/oras-go/v2/registry/remote/auth"

	"github.com/falcosecurity/falcoctl/internal/utils"
	"github.com/falcosecurity/falcoctl/pkg/oci"
	"github.com/falcosecurity/falcoctl/pkg/oci/authn"
	"github.com/falcosecurity/falcoctl/pkg/oci/registry"
	"github.com/falcosecurity/falcoctl/pkg/options"
)

type loginOptions struct {
	*options.CommonOptions
	hostname string
	username string
	password string
}

func (o *loginOptions) Validate(args []string) error {
	if len(args) != 0 {
		o.hostname = args[0]
	} else {
		o.hostname = oci.DefaultRegistry
	}
	return nil
}

// NewLoginCmd returns the login command.
func NewLoginCmd(ctx context.Context, opt *options.CommonOptions) *cobra.Command {
	o := loginOptions{
		CommonOptions: opt,
	}

	cmd := &cobra.Command{
		Use:                   "login hostname",
		DisableFlagsInUseLine: true,
		Short:                 "Login to an OCI registry",
		Long:                  "Login to an OCI registry to push and pull Falco rules and plugins",
		Args:                  cobra.MaximumNArgs(1),
		PreRun: func(cmd *cobra.Command, args []string) {
			o.Printer.CheckErr(o.Validate(args))
		},
		Run: func(cmd *cobra.Command, args []string) {
			o.Printer.CheckErr(o.RunLogin(ctx, args))
		},
	}

	cmd.Flags().StringVarP(&o.username, "user", "u", "", "username of the user to login with")
	cmd.Flags().StringVarP(&o.password, "password", "p", "", "password or token required for authentication")

	return cmd
}

// RunLogin executes the business logic for the login command.
func (o *loginOptions) RunLogin(ctx context.Context, args []string) error {
	var reg string

	if n := len(args); n == 1 {
		reg = args[0]
	} else {
		reg = oci.DefaultRegistry
	}

	var err error
	var user, token string

	// Login works if both -u and -p flags are used or none of them are used.
	if o.username == "" && o.password == "" {
		// In this case it just works interactively
		user, token, err = utils.GetCredentials(o.Printer)
		if err != nil {
			return err
		}
	} else if o.username == "" || o.password == "" {
		return fmt.Errorf("please use both --user and --password flags for the scriptable version of this command")
	}

	cred := &auth.Credential{
		Username: user,
		Password: token,
	}

	client := authn.NewClient(authn.WithCredentials(cred))
	r, err := registry.NewRegistry(reg, registry.WithClient(client))
	if err != nil {
		return err
	}

	if err := r.CheckConnection(ctx); err != nil {
		o.Printer.Verbosef("%s", err.Error())
		return fmt.Errorf("unable to connect to registry %q: %w", reg, err)
	}

	// Store validated credentials
	err = authn.Login(o.hostname, user, token)
	if err != nil {
		return err
	}

	o.Printer.Success.Println("Login succeeded")
	return nil
}
