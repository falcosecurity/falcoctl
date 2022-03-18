package cmd

import (
	"fmt"
	"github.com/falcosecurity/falcoctl/cmd/internal/validate"
	"github.com/falcosecurity/falcoctl/pkg/registry"
	"github.com/go-playground/validator/v10"
	"github.com/spf13/cobra"
	"net/http"
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
func NewSearchRegptions() *SearchRegOptions {
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
		Long:                  `Search a plugin inside the official Falco registry`,
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
