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

package follow

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"github.com/falcosecurity/falcoctl/internal/config"
	"github.com/falcosecurity/falcoctl/internal/follower"
	"github.com/falcosecurity/falcoctl/internal/utils"
	"github.com/falcosecurity/falcoctl/pkg/index"
	"github.com/falcosecurity/falcoctl/pkg/options"
)

const timeout = time.Second * 5

var longFollow = `Follow a list of artifacts from remote registry. It periodically
checks if the artifacts changed and downloads the latest version based on the configured
tags.

Artifacts are passed as arguments. By just providing the name of the artifact the
command will search for the artifact in the configured index files (see index command).
If found it will use the 'registry' and 'repository' as specifiend in the index file.

Example - Install and follow "cloudtrail" plugin using the "latest" (default) tag using the info found in the index file:
	falcoctl artifact follow cloudtrail

Example - Install and follow "cloudtrail:0.6.0" plugin using the "0.6.0" tag. Here we explicitly set the tag:
	falcoctl artifact follow cloudtrail:0.6.0

Example - Install and follow "cloudtrail" plugin and "cloutrail-rules" using the "latest" (default) tag:
	falcoctl artifact follow cloudtrail cloudtrail-rules


The command also supports the references for the artifacts composed by "registry" + "repository" + "tag":

Example - Install and follow "cloudtrail" plugins using the full artifact reference:
	falcoctl artifact follow ghcr.io/falcosecurity/plugins/ruleset/cloudtrail:0.6.0-rc1
`

type artifactFollowOptions struct {
	*options.CommonOptions
	rulesfilesDir string
	pluginsDir    string
	every         time.Duration
	closeChan     chan bool
}

// NewArtifactFollowCmd returns the artifact follow command.
func NewArtifactFollowCmd(ctx context.Context, opt *options.CommonOptions) *cobra.Command {
	o := artifactFollowOptions{
		CommonOptions: opt,
		closeChan:     make(chan bool),
	}

	cmd := &cobra.Command{
		Use:   "follow [ref1 [ref2 ...]] [flags]",
		Short: "Install a list of artifacts and continuously checks if there are updates",
		Long:  longFollow,
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			o.Printer.CheckErr(o.RunArtifactFollow(ctx, args))
		},
	}

	cmd.Flags().DurationVarP(&o.every, "every", "e", config.FollowResync, "Time interval how often it checks for a new version of the "+
		"artifact")
	// TODO (alacuku): move it in a dedicate data structure since they are in common with artifactInstall command.
	cmd.Flags().StringVarP(&o.rulesfilesDir, "rulesfiles-dir", "", config.RulesfilesDir,
		"Directory where to install rules")
	cmd.Flags().StringVarP(&o.pluginsDir, "plugins-dir", "", config.PluginsDir,
		"Directory where to install plugins")

	return cmd
}

// RunArtifactFollow executes the business logic for the artifact follow command.
func (o *artifactFollowOptions) RunArtifactFollow(ctx context.Context, args []string) error {
	o.Printer.Info.Printfln("Reading all configured index files from %q", config.IndexesFile)
	indexConfig, err := index.NewConfig(config.IndexesFile)
	if err != nil {
		return err
	}

	mergedIndexes, err := utils.Indexes(indexConfig, config.FalcoctlPath)
	if err != nil {
		return err
	}

	if len(mergedIndexes.Entries) < 1 {
		o.Printer.Warning.Println("No configured index. Consider to configure one using the 'index add' command.")
	}

	var wg sync.WaitGroup
	// Disable styling
	o.Printer.DisableStylingf()
	// For each artifact create a follower.
	var followers = make(map[string]*follower.Follower, 0)
	for _, a := range args {
		o.Printer.Info.Printfln("Creating follower for %q", a)
		ref, err := utils.ParseReference(mergedIndexes, a)
		if err != nil {
			return fmt.Errorf("unable to parse artifact reference for %q: %w", a, err)
		}

		cfg := &follower.Config{
			WaitGroup:         &wg,
			Resync:            o.every,
			RulefilesDir:      o.rulesfilesDir,
			PluginsDir:        o.pluginsDir,
			ArtifactReference: ref,
			Verbose:           o.IsVerbose(),
			CloseChan:         o.closeChan,
		}
		fol, err := follower.New(ctx, ref, o.Printer, cfg)
		if err != nil {
			return fmt.Errorf("unable to create the follower for ref %q: %w", ref, err)
		}
		wg.Add(1)
		followers[ref] = fol
	}
	// Enable styling
	o.Printer.EnableStyling()

	for k, f := range followers {
		o.Printer.Info.Printfln("Starting follower for %q", k)
		go f.Follow(ctx)
	}

	// Wait until we receive a signal to be terminated
	<-ctx.Done()

	// We are done, shutdown the followers.
	o.Printer.DefaultText.Printfln("closing followers...")
	close(o.closeChan)

	// Wait for the followers to shutdown or that the timer expires.
	doneChan := make(chan bool)

	go func() {
		wg.Wait()
		close(doneChan)
	}()

	select {
	case <-doneChan:
		o.Printer.DefaultText.Printfln("followers correctly stopped.")
	case <-time.After(timeout):
		o.Printer.DefaultText.Printfln("Timed out waiting for followers to exit")
	}

	return nil
}
