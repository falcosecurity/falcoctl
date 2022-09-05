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
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"

	"github.com/falcosecurity/falcoctl/pkg/oci"
	"github.com/falcosecurity/falcoctl/pkg/oci/authn"
	commonoptions "github.com/falcosecurity/falcoctl/pkg/options"
	"github.com/falcosecurity/falcoctl/pkg/output"
)

type loginOptions struct {
	*commonoptions.CommonOptions
	hostname string
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
func NewLoginCmd(opt *commonoptions.CommonOptions) *cobra.Command {
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
			o.Printer.CheckErr(o.RunLogin(args))
		},
	}

	return cmd
}

// RunLogin executes the business logic for the login command.
func (o *loginOptions) RunLogin(args []string) error {
	user, token, err := getCredentials(o.Printer)
	if err != nil {
		o.Printer.Error.Println(err.Error())
		return err
	}

	cred := auth.Credential{
		Username: user,
		Password: token,
	}

	client := authn.NewClient(cred)
	if err != nil {
		o.Printer.Error.Println(err.Error())
		return err
	}

	// Ensure credentials are valid
	registry, err := remote.NewRegistry(o.hostname)
	if err != nil {
		return err
	}
	registry.Client = client
	if err = registry.Ping(context.Background()); err != nil {
		return err
	}

	// Store validated credentials
	err = authn.Login(o.hostname, user, token)
	if err != nil {
		o.Printer.Error.Println(err.Error())
		return err
	}

	o.Printer.DefaultText.Println("Login succeeded")
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
