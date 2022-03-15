package cmd

import (
	"fmt"
	"net/http"

	"github.com/falcosecurity/falcoctl/pkg/registry"
	logger "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func NewSearchRegistryCmd(options CommandOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:                   "registry",
		DisableFlagsInUseLine: true,
		Short:                 "Search a plugin inside the official Falco registry",
		Long:                  `Search a plugin inside the official Falco registry`,
		Run: func(cmd *cobra.Command, args []string) {
			var output string
			all, err := cmd.Flags().GetBool("all")
			if err != nil {
				logger.Error(err)
			}

			if !all && len(args) == 0 {
				logger.Error("Please provide one or more arguments or --all/-a flag")
				return
			}
			resp, err := http.Get("https://raw.githubusercontent.com/falcosecurity/plugins/master/registry.yaml")
			if err != nil {
				return
			}
			body := resp.Body
			defer body.Close()

			registry, err := registry.LoadRegistry(&body)
			if err != nil {
				logger.Error(err)
				return
			}

			if all {
				output, err = registry.Plugins.ToString()
			} else {
				plugins := registry.SearchByKeywords(args)
				output, err = plugins.ToString()
			}

			if err != nil {
				logger.Error(err)
			}

			fmt.Println(output)
		},
	}

	flags := cmd.PersistentFlags()
	flags.BoolP("all", "a", false, "print all entries in the registry")

	return cmd
}
