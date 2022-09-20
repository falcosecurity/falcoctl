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

package cmd

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"
	"oras.land/oras-go/v2/registry/remote/auth"

	"github.com/falcosecurity/falcoctl/cmd/internal/utils"
	"github.com/falcosecurity/falcoctl/pkg/oci"
	"github.com/falcosecurity/falcoctl/pkg/oci/authn"
	"github.com/falcosecurity/falcoctl/pkg/options"
	"github.com/falcosecurity/falcoctl/pkg/output"
)

type loginOptions struct {
	*options.CommonOptions
	hostname string
	username string
	password string
}

func (o *loginOptions) Validate(args []string) error {
	return nil
}

// NewLoginCmd returns the login command.
func NewLoginCmd(ctx context.Context, opt *options.CommonOptions) *cobra.Command {
	o := loginOptions{
		CommonOptions: opt,
	}

	cmd := &cobra.Command{
		Use:                   "login [host -u user -p token]",
		DisableFlagsInUseLine: false,
		Short:                 "Login to an OCI registry",
		Long:                  "Login to an OCI registry to push and pull Falco rules and plugins",
		Args:                  cobra.MaximumNArgs(3),
		PreRun: func(cmd *cobra.Command, args []string) {
			o.Printer.CheckErr(o.Validate(args))
		},
		Run: func(cmd *cobra.Command, args []string) {
			o.Printer.CheckErr(o.RunLogin(ctx, args))
		},
	}
	cmd.Flags().StringVarP(&o.hostname, "host", "", "", "Hostname of the registry")
	cmd.Flags().StringVarP(&o.username, "user", "u", "", "Username (required if password is set)")
	cmd.Flags().StringVarP(&o.password, "token", "p", "", "Password (required if username is set)")
	cmd.MarkFlagsRequiredTogether("user", "token")

	cmd.Flags().SortFlags = false
	cmd.Flags().Lookup("host").NoOptDefVal = oci.DefaultRegistry

	return cmd
}

// RunLogin executes the business logic for the login command.
func (o *loginOptions) RunLogin(ctx context.Context, args []string) error {
	var registry string

	if n := len(args); n == 1 {
		registry = args[0]
	} else {
		registry = oci.DefaultRegistry
	}

	var err error
	user, token := o.username, o.password

	if o.username == "" || o.password == "" {
		user, token, err = getCredentials(o.Printer)
		if err != nil {
			return err
		}
	}

	cred := &auth.Credential{
		Username: user,
		Password: token,
	}

	if err := utils.CheckRegistryConnection(ctx, cred, registry, o.Printer); err != nil {
		o.Printer.Verbosef("%s", err.Error())
		return fmt.Errorf("unable to connect to registry %q", registry)
	}

	// Store validated credentials
	err = authn.Login(o.hostname, user, token)
	if err != nil {
		return err
	}

	o.Printer.Success.Println("Login succeeded")
	return nil
}

func getCredentials(p *output.Printer) (username, password string, err error) {
	reader := bufio.NewReader(os.Stdin)

	p.DefaultText.Print("Username: ")
	username, err = reader.ReadString('\n')
	if err != nil {
		return "", "", err
	}

	p.DefaultText.Print("Password: ")
	bytePassword, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return "", "", err
	}

	p.DefaultText.Println()

	password = string(bytePassword)
	return strings.TrimSpace(username), strings.TrimSpace(password), nil
}
