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
	"fmt"
	"net/http"

	"github.com/go-playground/validator/v10"
	"github.com/spf13/cobra"

	"github.com/falcosecurity/falcoctl/cmd/internal/validate"
	"github.com/falcosecurity/falcoctl/pkg/registry"
)

// Defaults
const (
	DefaultRegUrl   = "https://raw.githubusercontent.com/falcosecurity/plugins/master/registry.yaml"
	DefaultPrintAll = false
)

var _ CommandOptions = &SearchRegOptions{}

// TLSOptions represents the `install tls` command options
type SearchRegOptions struct {
	registry string `validate:"registryurl" name:"registry url" default:"https://raw.githubusercontent.com/falcosecurity/plugins/master/registry.yaml"`
	printall bool
}

// AddFlags adds flag to c
func (o *SearchRegOptions) AddFlags(c *cobra.Command) {
	flags := c.Flags()
	flags.StringVarP(&o.registry, "registryurl", "r", o.registry, "Registry url to search")
	flags.BoolVarP(&o.printall, "all", "a", o.printall, "Print all the entries")
}

// Validate validates the `search registry` command options
func (o *SearchRegOptions) Validate(c *cobra.Command, args []string) error {
	if err := validate.V.Struct(o); err != nil {
		return err.(validator.ValidationErrors)
	}
	return nil
}

// NewRegOptions instantiates the `search registry` command options
func NewSearchRegOptions() *SearchRegOptions {
	return &SearchRegOptions{
		registry: DefaultRegUrl,
		printall: DefaultPrintAll,
	}
}

func NewSearchRegistryCmd(options CommandOptions) *cobra.Command {
	o := options.(*SearchRegOptions)

	cmd := &cobra.Command{
		Use:                   "registry",
		DisableFlagsInUseLine: true,
		Short:                 "Search a plugin inside the official Falco registry",
		Long:                  "Search a plugin inside the official Falco registry",
		PreRunE:               o.Validate,
		RunE: func(cmd *cobra.Command, args []string) error {
			var output string
			if !o.printall && len(args) == 0 {
				return fmt.Errorf("please provide one or more arguments or --all/-a flag")
			}
			resp, err := http.Get(o.registry)
			if err != nil {
				return fmt.Errorf("unable to GET from URL \"%s\": %s", o.registry, err.Error())
			}
			body := resp.Body
			defer body.Close()

			reg, err := registry.LoadRegistry(&body)
			if err != nil {
				return fmt.Errorf("could not load registry: %s", err.Error())
			}

			if o.printall {
				output, err = reg.Plugins.ToString()
			} else {
				plugins := reg.SearchByKeywords(args)
				output, err = plugins.ToString()
			}
			if err != nil {
				return err
			}
			fmt.Println(output)
			return nil
		},
	}
	o.AddFlags(cmd)
	return cmd
}
