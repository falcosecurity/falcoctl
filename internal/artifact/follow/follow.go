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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"sync"
	"time"

	"github.com/blang/semver"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/falcosecurity/falcoctl/internal/config"
	"github.com/falcosecurity/falcoctl/internal/follower"
	"github.com/falcosecurity/falcoctl/internal/utils"
	"github.com/falcosecurity/falcoctl/pkg/index"
	"github.com/falcosecurity/falcoctl/pkg/options"
)

const (
	timeout = time.Second * 5

	longFollow = `Follow a list of artifacts from remote registry. It periodically
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
)

type artifactFollowOptions struct {
	*options.CommonOptions
	*options.RegistryOptions
	rulesfilesDir string
	pluginsDir    string
	workingDir    string
	every         time.Duration
	falcoVersions string
	versions      config.FalcoVersions
	closeChan     chan bool
}

// NewArtifactFollowCmd returns the artifact follow command.
func NewArtifactFollowCmd(ctx context.Context, opt *options.CommonOptions) *cobra.Command {
	o := artifactFollowOptions{
		CommonOptions:   opt,
		RegistryOptions: &options.RegistryOptions{},
		closeChan:       make(chan bool),
	}

	cmd := &cobra.Command{
		Use:   "follow [ref1 [ref2 ...]] [flags]",
		Short: "Install a list of artifacts and continuously checks if there are updates",
		Long:  longFollow,
		PreRun: func(cmd *cobra.Command, args []string) {
			// Override "every" flag with viper config if not set by user.
			f := cmd.Flags().Lookup("every")
			if f == nil {
				// should never happen
				o.Printer.CheckErr(fmt.Errorf("unable to retrieve flag every"))
			} else if !f.Changed && viper.IsSet(config.FollowerEveryKey) {
				val := viper.Get(config.FollowerEveryKey)
				if err := cmd.Flags().Set(f.Name, fmt.Sprintf("%v", val)); err != nil {
					o.Printer.CheckErr(fmt.Errorf("unable to overwrite \"every\" flag: %w", err))
				}
			}

			// Override "falco-versions" flag with viper config if not set by user.
			f = cmd.Flags().Lookup("falco-versions")
			if f == nil {
				// should never happen
				o.Printer.CheckErr(fmt.Errorf("unable to retrieve flag falco-versions"))
			} else if !f.Changed && viper.IsSet(config.FollowerFalcoVersionsKey) {
				val := viper.Get(config.FollowerFalcoVersionsKey)
				if err := cmd.Flags().Set(f.Name, fmt.Sprintf("%v", val)); err != nil {
					o.Printer.CheckErr(fmt.Errorf("unable to overwrite \"falco-versions\" flag: %w", err))
				}
			}

			// Get Falco versions via HTTP endpoint
			if err := o.retrieveFalcoVersions(ctx); err != nil {
				o.Printer.CheckErr(fmt.Errorf("unable to retrieve Falco versions, please check if it is running "+
					"and correctly exposing the version endpoint: %w", err))
			}
		},
		Run: func(cmd *cobra.Command, args []string) {
			o.Printer.CheckErr(o.RunArtifactFollow(ctx, args))
		},
	}

	o.RegistryOptions.AddFlags(cmd)
	cmd.Flags().DurationVarP(&o.every, "every", "e", config.FollowResync, "Time interval how often it checks for a new version of the "+
		"artifact")
	// TODO (alacuku): move it in a dedicate data structure since they are in common with artifactInstall command.
	cmd.Flags().StringVarP(&o.rulesfilesDir, "rulesfiles-dir", "", config.RulesfilesDir,
		"Directory where to install rules")
	cmd.Flags().StringVarP(&o.pluginsDir, "plugins-dir", "", config.PluginsDir,
		"Directory where to install plugins")
	cmd.Flags().StringVar(&o.workingDir, "working-dir", "", "Directory where to save temporary files")
	cmd.Flags().StringVar(&o.falcoVersions, "falco-versions", "http://localhost:8765/versions",
		"Where to retrieve versions, it can be either an URL or a path to a file")
	return cmd
}

// RunArtifactFollow executes the business logic for the artifact follow command.
func (o *artifactFollowOptions) RunArtifactFollow(ctx context.Context, args []string) error {
	// Retrieve configuration for follower
	configuredFollower, err := config.Follower()
	if err != nil {
		o.Printer.CheckErr(fmt.Errorf("unable to retrieved the configured follower: %w", err))
	}

	// Set args as configured if no arg was passed
	if len(args) == 0 {
		if len(configuredFollower.Artifacts) == 0 {
			return fmt.Errorf("no artifacts to follow, please configure artifacts or pass them as arguments to this command")
		}
		args = configuredFollower.Artifacts
	}

	o.Printer.Info.Printfln("Reading all configured index files from %q", config.IndexesFile)
	indexConfig, err := index.NewConfig(config.IndexesFile)
	if err != nil {
		return err
	}

	mergedIndexes, err := utils.Indexes(indexConfig, config.IndexesDir)
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
		o.Printer.Info.Printfln("Creating follower for %q, check every %s", a, o.every.String())
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
			PlainHTTP:         o.PlainHTTP,
			Verbose:           o.IsVerbose(),
			CloseChan:         o.closeChan,
			WorkingDir:        o.workingDir,
			FalcoVersions:     o.versions,
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

func (o *artifactFollowOptions) retrieveFalcoVersions(ctx context.Context) error {
	_, err := url.ParseRequestURI(o.falcoVersions)
	if err != nil {
		return fmt.Errorf("unable to parse URI: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", o.falcoVersions, http.NoBody)
	if err != nil {
		return fmt.Errorf("cannot fetch Falco version: %w", err)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("unable to get versions from URL %q: %w", o.falcoVersions, err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("unable to read response body: %w", err)
	}

	err = json.Unmarshal(data, &o.versions)
	if err != nil {
		return fmt.Errorf("error unmarshalling: %w", err)
	}

	for k, v := range o.versions {
		switch reflect.TypeOf(v).Kind() {
		case reflect.String:
			// In this case, we treat the input as semver and we try to parse it
			o.versions[k], err = semver.Parse(v.(string))
			if err != nil {
				return fmt.Errorf("unable to parse Falco version %q: %w", v, err)
			}
		case reflect.Float64:
			o.versions[k] = int(v.(float64)) // convert to int
		default:
			return fmt.Errorf("got unexpected type while retrieving Falco versions: %s, %T", k, v)
		}
	}

	return nil
}
