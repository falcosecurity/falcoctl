package cmd

import "github.com/spf13/cobra"

//Defaults
const ()

// ListOptions represents the install command options
type ListOptions struct {
	*ListRepoOptions
	RepoPath string
	RepoFile string
}

// Validate validates the `list` command options
func (o *ListOptions) Validate(c *cobra.Command, args []string) error {
	//TODO
	return nil
}

func (o *ListOptions) AddFlags(c *cobra.Command) {
}

// NewRepoOptions instantiates the `repo` command options
func NewListOptions() CommandOptions {
	return &ListOptions{
		ListRepoOptions: NewListRepoOptions(),
		RepoPath:        defaultRepoPath,
		RepoFile:        defaultRepoFile,
	}
}

func NewListCmd(options CommandOptions) *cobra.Command {
	o := options.(*ListOptions)
	cmd := &cobra.Command{
		Use:                   "list",
		DisableFlagsInUseLine: true,
		Short:                 "Print list of resources",
		Long:                  "Print list of resources",
	}

	cmd.AddCommand(NewListRepoCmd(o))

	return cmd
}
