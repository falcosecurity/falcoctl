// Copyright 2023 The Falco Authors
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
	"sync"
	"time"

	"github.com/robfig/cron/v3"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/falcosecurity/falcoctl/cmd/artifact/install"
	"github.com/falcosecurity/falcoctl/internal/config"
	"github.com/falcosecurity/falcoctl/internal/follower"
	"github.com/falcosecurity/falcoctl/internal/utils"
	"github.com/falcosecurity/falcoctl/pkg/index"
	"github.com/falcosecurity/falcoctl/pkg/oci"
	"github.com/falcosecurity/falcoctl/pkg/options"
	"github.com/falcosecurity/falcoctl/pkg/output"
)

const (
	timeout = time.Second * 5

	longFollow = `This command allows you to keep up-to-date one or more given artifacts.
It checks for updates on a periodic basis and then downloads and installs the latest version, 
as specified by the passed tags. 

Artifact references and flags are passed as arguments through:
- command line options
- environment variables
- configuration file
The arguments passed through these different modalities are prioritized in the following order:
command line options, environment variables, and finally the configuration file. This means that
if an argument is passed through multiple modalities, the value set in the command line options
will take precedence over the value set in environment variables, which will in turn take precedence
over the value set in the configuration file.
Please note that when passing multiple artifact references via an environment variable, they must be
separated by a semicolon ';' and the environment variable used for references is called
FALCOCT_ARTIFACT_FOLLOW_REFS. Other arguments, if passed through environment variables, should start
with "FALCOCTL_" and be followed by the hierarchical keys used in the configuration file separated by
an underscore "_".

A reference is either a simple name or a fully qualified reference ("<registry>/<repository>"), 
optionally followed by ":<tag>" (":latest" is assumed by default when no tag is given).

When providing just the name of the artifact, the command will search for the artifacts in 
the configured index files, and if found, it will use the registry and repository specified 
in the indexes.

Example - Install and follow "latest" tag of "k8saudit-rules" artifact by relying on index metadata:
	falcoctl artifact follow k8saudit-rules

Example - Install and follow all updates from "k8saudit-rules" 0.5.x release series:
	falcoctl artifact follow k8saudit-rules:0.5

Example - Install and follow "cloudtrail" plugins using a fully qualified reference:
	falcoctl artifact follow ghcr.io/falcosecurity/plugins/ruleset/k8saudit:latest
`
)

type artifactFollowOptions struct {
	*options.CommonOptions
	*options.RegistryOptions
	rulesfilesDir string
	pluginsDir    string
	tmpDir        string
	every         time.Duration
	cron          string
	falcoVersions string
	versions      config.FalcoVersions
	timeout       time.Duration
	closeChan     chan bool
	allowedTypes  oci.ArtifactTypeSlice
}

// NewArtifactFollowCmd returns the artifact follow command.
func NewArtifactFollowCmd(ctx context.Context, opt *options.CommonOptions) *cobra.Command {
	o := artifactFollowOptions{
		CommonOptions:   opt,
		RegistryOptions: &options.RegistryOptions{},
		closeChan:       make(chan bool),
		versions:        config.FalcoVersions{},
	}

	cmd := &cobra.Command{
		Use:           "follow [ref1 [ref2 ...]] [flags]",
		Short:         "Install a list of artifacts and continuously checks if there are updates",
		Long:          longFollow,
		SilenceErrors: true,
		SilenceUsage:  true,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			// Override "every" flag with viper config if not set by user.
			f := cmd.Flags().Lookup("every")
			if f == nil {
				// should never happen
				return fmt.Errorf("unable to retrieve flag every")
			} else if !f.Changed && viper.IsSet(config.ArtifactFollowEveryKey) {
				val := viper.Get(config.ArtifactFollowEveryKey)
				if err := cmd.Flags().Set(f.Name, fmt.Sprintf("%v", val)); err != nil {
					return fmt.Errorf("unable to overwrite \"every\" flag: %w", err)
				}
			}

			// Override "cron" flag with viper config if not set by user.
			f = cmd.Flags().Lookup("cron")
			if f == nil {
				// should never happen
				return fmt.Errorf("unable to retrieve flag cron")
			} else if !f.Changed && viper.IsSet(config.ArtifactFollowCronKey) {
				val := viper.Get(config.ArtifactFollowCronKey)
				if err := cmd.Flags().Set(f.Name, fmt.Sprintf("%v", val)); err != nil {
					return fmt.Errorf("unable to overwrite \"cron\" flag: %w", err)
				}
			}

			// Override "falco-versions" flag with viper config if not set by user.
			f = cmd.Flags().Lookup("falco-versions")
			if f == nil {
				// should never happen
				return fmt.Errorf("unable to retrieve flag falco-versions")
			} else if !f.Changed && viper.IsSet(config.ArtifactFollowFalcoVersionsKey) {
				val := viper.Get(config.ArtifactFollowFalcoVersionsKey)
				if err := cmd.Flags().Set(f.Name, fmt.Sprintf("%v", val)); err != nil {
					return fmt.Errorf("unable to overwrite \"falco-versions\" flag: %w", err)
				}
			}

			// Override "rulesfiles-dir" flag with viper config if not set by user.
			f = cmd.Flags().Lookup(install.FlagRulesFilesDir)
			if f == nil {
				// should never happen
				return fmt.Errorf("unable to retrieve flag %q", install.FlagRulesFilesDir)
			} else if !f.Changed && viper.IsSet(config.ArtifactFollowRulesfilesDirKey) {
				val := viper.Get(config.ArtifactFollowRulesfilesDirKey)
				if err := cmd.Flags().Set(f.Name, fmt.Sprintf("%v", val)); err != nil {
					return fmt.Errorf("unable to overwrite %q flag: %w", install.FlagRulesFilesDir, err)
				}
			}

			// Override "plugins-dir" flag with viper config if not set by user.
			f = cmd.Flags().Lookup(install.FlagPluginsFilesDir)
			if f == nil {
				// should never happen
				return fmt.Errorf("unable to retrieve flag %q", install.FlagPluginsFilesDir)
			} else if !f.Changed && viper.IsSet(config.ArtifactFollowPluginsDirKey) {
				val := viper.Get(config.ArtifactFollowPluginsDirKey)
				if err := cmd.Flags().Set(f.Name, fmt.Sprintf("%v", val)); err != nil {
					return fmt.Errorf("unable to overwrite %q flag: %w", install.FlagPluginsFilesDir, err)
				}
			}

			// Override "tmp-dir" flag with viper config if not set by user.
			f = cmd.Flags().Lookup("tmp-dir")
			if f == nil {
				// should never happen
				return fmt.Errorf("unable to retrieve flag tmp-dir")
			} else if !f.Changed && viper.IsSet(config.ArtifactFollowTmpDirKey) {
				val := viper.Get(config.ArtifactFollowTmpDirKey)
				if err := cmd.Flags().Set(f.Name, fmt.Sprintf("%v", val)); err != nil {
					return fmt.Errorf("unable to overwrite \"tmp-dir\" flag: %w", err)
				}
			}

			// Override "allowed-types" flag with viper config if not set by user.
			f = cmd.Flags().Lookup(install.FlagAllowedTypes)
			if f == nil {
				// should never happen
				return fmt.Errorf("unable to retrieve flag %s", install.FlagAllowedTypes)
			} else if !f.Changed && viper.IsSet(config.ArtifactAllowedTypesKey) {
				val, err := config.ArtifactAllowedTypes()
				if err != nil {
					return err
				}
				if err := cmd.Flags().Set(f.Name, val.String()); err != nil {
					return fmt.Errorf("unable to overwrite %q flag: %w", install.FlagAllowedTypes, err)
				}
			}

			// Get Falco versions via HTTP endpoint
			if err := o.retrieveFalcoVersions(ctx); err != nil {
				return fmt.Errorf("unable to retrieve Falco versions, please check if it is running "+
					"and correctly exposing the version endpoint: %w", err)
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return o.RunArtifactFollow(ctx, args)
		},
	}

	o.RegistryOptions.AddFlags(cmd)
	cmd.Flags().DurationVarP(&o.every, "every", "e", config.FollowResync, "Time interval how often it checks for a new version of the "+
		"artifact. Cannot be used together with 'cron' option.")
	cmd.Flags().StringVar(&o.cron, "cron", "", "Cron-like string to specify interval how often it checks for a new version of the artifact."+
		" Cannot be used together with 'every' option.")
	// TODO (alacuku): move it in a dedicate data structure since they are in common with artifactInstall command.
	cmd.Flags().StringVarP(&o.rulesfilesDir, install.FlagRulesFilesDir, "", config.RulesfilesDir,
		"Directory where to install rules")
	cmd.Flags().StringVarP(&o.pluginsDir, install.FlagPluginsFilesDir, "", config.PluginsDir,
		"Directory where to install plugins")
	cmd.Flags().StringVar(&o.tmpDir, "tmp-dir", "", "Directory where to save temporary files")
	cmd.Flags().StringVar(&o.falcoVersions, "falco-versions", "http://localhost:8765/versions",
		"Where to retrieve versions, it can be either an URL or a path to a file")
	cmd.Flags().DurationVar(&o.timeout, "timeout", defaultBackoffConfig.MaxDelay,
		"Timeout for initial connection to the Falco versions endpoint")
	cmd.Flags().Var(&o.allowedTypes, install.FlagAllowedTypes,
		fmt.Sprintf(`list of artifact types that can be followed. If not specified or configured, all types are allowed.
It accepts comma separated values or it can be repeated multiple times.
Examples: 
	--%s="rulesfile,plugin"
	--%s=rulesfile --%s=plugin`, install.FlagAllowedTypes, install.FlagAllowedTypes, install.FlagAllowedTypes))
	cmd.MarkFlagsMutuallyExclusive("cron", "every")

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

	var sched cron.Schedule
	if o.cron != "" {
		sched, err = cron.ParseStandard(o.cron)
		if err != nil {
			return fmt.Errorf("unable to parse cron '%s': %w", o.cron, err)
		}
	} else {
		sched = scheduledDuration{o.every}
	}

	var wg sync.WaitGroup
	// Disable styling
	o.Printer.DisableStylingf()
	// For each artifact create a follower.
	var followers = make(map[string]*follower.Follower, 0)
	for _, a := range args {
		if o.cron != "" {
			o.Printer.Info.Printfln("Creating follower for %q, with check using cron %s", a, o.cron)
		} else {
			o.Printer.Info.Printfln("Creating follower for %q, with check every %s", a, o.every.String())
		}
		ref, err := o.IndexCache.ResolveReference(a)
		if err != nil {
			return fmt.Errorf("unable to parse artifact reference for %q: %w", a, err)
		}

		cfg := &follower.Config{
			WaitGroup:         &wg,
			Resync:            sched,
			RulesfilesDir:     o.rulesfilesDir,
			PluginsDir:        o.pluginsDir,
			ArtifactReference: ref,
			PlainHTTP:         o.PlainHTTP,
			Verbose:           o.IsVerbose(),
			CloseChan:         o.closeChan,
			TmpDir:            o.tmpDir,
			FalcoVersions:     o.versions,
			AllowedTypes:      o.allowedTypes,
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

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, o.falcoVersions, http.NoBody)
	if err != nil {
		return fmt.Errorf("cannot fetch Falco version: %w", err)
	}

	backoffConfig := defaultBackoffConfig
	backoffConfig.MaxDelay = o.timeout

	client := &http.Client{
		Transport: &backoffTransport{
			Base:    http.DefaultTransport,
			Printer: o.Printer,
			Config:  backoffConfig,
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("unable to get versions from URL %q: %w", o.falcoVersions, err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("unable to read response body: %w", err)
	}

	var dataUnmarshalled map[string]interface{}

	err = json.Unmarshal(data, &dataUnmarshalled)
	if err != nil {
		return fmt.Errorf("error unmarshalling: %w", err)
	}

	for key, value := range dataUnmarshalled {
		// todo(alacuku): how to handle types other than strings? Silently ignoring for now...
		if strValue, ok := value.(string); ok {
			o.versions[key] = strValue
		}
	}

	return nil
}

// Config defines the configuration options for backoff.
type backoffConfig struct {
	// BaseDelay is the amount of time to backoff after the first failure.
	BaseDelay time.Duration
	// Multiplier is the factor with which to multiply backoffs after a
	// failed retry. Should ideally be greater than 1.
	Multiplier float64
	// Jitter is the factor with which backoffs are randomized.
	// todo: not yet implemented
	// Jitter float64
	// MaxDelay is the upper bound of backoff delay.
	MaxDelay time.Duration
}

var defaultBackoffConfig = backoffConfig{
	BaseDelay:  1.0 * time.Second,
	Multiplier: 1.6,
	// Jitter:     0.2, todo: not yet implemented
	MaxDelay: 120 * time.Second,
}

type backoffTransport struct {
	Base      http.RoundTripper
	Printer   *output.Printer
	Config    backoffConfig
	attempts  int
	startTime time.Time
}

func (bt *backoffTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var err error
	var resp *http.Response

	bt.startTime = time.Now()
	bt.attempts = 0

	bt.Printer.Verbosef("Retrieving versions from Falco (timeout %s) ...", bt.Config.MaxDelay)

	for {
		resp, err = bt.Base.RoundTrip(req)
		if err != nil {
			if req.Context().Err() != nil {
				return nil, req.Context().Err()
			}
			sleep := bt.Config.backoff(bt.attempts)

			wakeTime := time.Now().Add(sleep)
			if wakeTime.Sub(bt.startTime) > bt.Config.MaxDelay {
				return resp, fmt.Errorf("timeout occurred while retrieving versions from Falco")
			}

			bt.Printer.Verbosef("error: %s. Trying again in %s", err.Error(), sleep.String())
			time.Sleep(sleep)
		} else {
			bt.Printer.Verbosef("Successfully retrieved versions from Falco ...")
			return resp, err
		}

		bt.attempts++
	}
}

// Backoff returns the amount of time to wait before the next retry given the
// number of retries.
func (bc backoffConfig) backoff(retries int) time.Duration {
	if retries == 0 {
		return bc.BaseDelay
	}
	backoff, max := float64(bc.BaseDelay), float64(bc.MaxDelay)
	for backoff < max && retries > 0 {
		backoff *= bc.Multiplier
		retries--
	}
	if backoff > max {
		backoff = max
	}
	// Randomize backoff delays so that if a cluster of requests start at
	// the same time, they won't operate in lockstep.
	// todo: implement jitter
	// backoff *= 1 + bc.Jitter*(math.Float64()*2-1)
	if backoff < 0 {
		return 0
	}

	return time.Duration(backoff)
}

type scheduledDuration struct {
	time.Duration
}

func (sd scheduledDuration) Next(tm time.Time) time.Time {
	return tm.Add(sd.Duration)
}
