package cmd

import "github.com/spf13/cobra"

// InstallOptions represents the install command options
type SearchOptions struct {
	*SearchRegOptions
}

// Validate validates the `install` command options
func (o *SearchOptions) Validate(c *cobra.Command, args []string) error {
	// todo > validate path exists and is writable here
	return nil
}

// NewSearchOptions instantiates the `search` command options
func NewSearchOptions() CommandOptions {
	return &SearchOptions{
		SearchRegOptions: NewSearchRegOptions(),
	}
}

func NewSearchCmd(options CommandOptions) *cobra.Command {
	o := options.(*SearchOptions)
	cmd := &cobra.Command{
		Use:                   "search",
		DisableFlagsInUseLine: true,
		Short:                 "Search a component with falcoctl",
		Long:                  "Search a component with falcoctl",
	}

	cmd.AddCommand(NewSearchRegistryCmd(o.SearchRegOptions))

	return cmd
}
