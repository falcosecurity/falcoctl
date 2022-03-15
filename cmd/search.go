package cmd

import "github.com/spf13/cobra"

func NewSearchCmd(options CommandOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:                   "search",
		DisableFlagsInUseLine: true,
		Short:                 "Search a component with falcoctl",
		Long:                  "Search a component with falcoctl",
	}

	cmd.AddCommand(NewSearchRegistryCmd(nil))

	return cmd
}
