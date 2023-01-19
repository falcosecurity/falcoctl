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

package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/docker/docker/pkg/homedir"
	"github.com/mitchellh/mapstructure"
	"github.com/spf13/viper"
)

var (
	// ConfigDir configuration directory for falcoctl.
	ConfigDir string
	// FalcoctlPath path inside the configuration directory where the falcoctl stores its config files.
	FalcoctlPath string
	// IndexesFile name of the file where the indexes info is stored. It lives under FalcoctlPath.
	IndexesFile string
	// IndexesDir is where the actual indexes are stored. It is a directory that lives under FalcoctlPath.
	IndexesDir string
	// ClientCredentialsFile name of the file where oauth client credentials are stored. It lives under FalcoctlPath.
	ClientCredentialsFile string
	// DefaultIndex is the default index for the falcosecurity organization.
	DefaultIndex Index
	// DefaultFollower represents the default following options.
	DefaultFollower Follow
)

const (
	// EnvPrefix is the prefix for all the environment variables.
	EnvPrefix = "FALCOCTL"
	// ConfigPath is the path to the default config.
	ConfigPath = "/etc/falcoctl/falcoctl.yaml"
	// PluginsDir default path where plugins are installed.
	PluginsDir = "/usr/share/falco/plugins"
	// RulesfilesDir default path where rulesfiles are installed.
	RulesfilesDir = "/etc/falco"
	// FollowResync time interval how often it checks for newer version of the artifact.
	// Default values is set every 24 hours.
	FollowResync = time.Hour * 24

	// Viper configuration keys.

	// OauthAuthsKey is the Viper key for OAuth authentication configuration.
	OauthAuthsKey = "oauthauths"
	// BasicAuthsKey is the Viper key for basic authentication configuration.
	BasicAuthsKey = "basicauths"
	// IndexesKey is the Viper key for indexes configuration.
	IndexesKey = "indexes"
	// FollowerEveryKey is the Viper key for follower "every" configuration.
	FollowerEveryKey = "follower.every"
	// FollowerArtifactsKey is the Viper key for follower "artifacts" configuration.
	FollowerArtifactsKey = "follower.artifacts"
	// FollowerFalcoVersionsKey is the Viper key for follower "falcoVersions" configuration.
	FollowerFalcoVersionsKey = "follower.falcoversions"
	// FollowerRulesfilesDirKey is the Viper key for follower "rulesFilesDir" configuration.
	FollowerRulesfilesDirKey = "follower.rulesfilesdir"
	// FollowerPluginsDirKey is the Viper key for follower "pluginsDir" configuration.
	FollowerPluginsDirKey = "follower.pluginsdir"
	// FollowerWorkingDirKey is the Viper key for follower "pluginsDir" configuration.
	FollowerWorkingDirKey = "follower.workingdir"
	// InstallerArtifactsKey is the Viper key for installer "artifacts" configuration.
	InstallerArtifactsKey = "installer.artifacts"
	// InstallerRulesfilesDirKey is the Viper key for follower "rulesFilesDir" configuration.
	InstallerRulesfilesDirKey = "installer.rulesfilesdir"
	// InstallerPluginsDirKey is the Viper key for follower "pluginsDir" configuration.
	InstallerPluginsDirKey = "installer.pluginsdir"
)

// Index represents a configured index.
type Index struct {
	Name string `mapstructure:"name"`
	URL  string `mapstructure:"url"`
}

// OauthAuth represents an OAuth credential.
type OauthAuth struct {
	Registry     string `mapstructure:"registry"`
	ClientSecret string `mapstructure:"clientSecret"`
	ClientID     string `mapstructure:"clientID"`
	TokenURL     string `mapstructure:"tokenURL"`
}

// BasicAuth represents a Basic credential.
type BasicAuth struct {
	Registry string `mapstructure:"registry"`
	User     string `mapstructure:"user"`
	Password string `mapstructure:"password"`
}

// Follow represents the follower configuration.
type Follow struct {
	Every         time.Duration `mapstructure:"every"`
	Artifacts     []string      `mapstructure:"artifacts"`
	FalcoVersions string        `mapstructure:"falcoVersions"`
	RulesfilesDir string        `mapstructure:"rulesFilesDir"`
	PluginsDir    string        `mapstructure:"pluginsDir"`
	WorkingDir    string        `mapstructure:"pluginsDir"`
}

// Install represents the installer configuration.
type Install struct {
	Artifacts     []string `mapstructure:"artifacts"`
	RulesfilesDir string   `mapstructure:"rulesFilesDir"`
	PluginsDir    string   `mapstructure:"pluginsDir"`
}

func init() {
	ConfigDir = filepath.Join(homedir.Get(), ".config")
	FalcoctlPath = filepath.Join(ConfigDir, "falcoctl")
	IndexesFile = filepath.Join(FalcoctlPath, "indexes.yaml")
	IndexesDir = filepath.Join(FalcoctlPath, "indexes")
	ClientCredentialsFile = filepath.Join(FalcoctlPath, "clientcredentials.json")
	DefaultIndex = Index{
		Name: "falcosecurity",
		URL:  "https://falcosecurity.github.io/falcoctl/index.yaml",
	}
	DefaultFollower = Follow{
		Every:         time.Hour * 24,
		Artifacts:     []string{"falco-rules:1", "application-rules:1"},
		FalcoVersions: "http://localhost:8765/versions",
	}
}

// Load is used to load the config file.
func Load(path string) error {
	viper.SetConfigName("config")

	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return err
	}

	viper.AddConfigPath(filepath.Dir(absolutePath))
	viper.SetConfigType("yaml")

	// Set default index
	viper.SetDefault(IndexesKey, []Index{DefaultIndex})

	// Set default follower options
	viper.SetDefault(FollowerEveryKey, DefaultFollower.Every)
	viper.SetDefault(FollowerArtifactsKey, DefaultFollower.Artifacts)
	viper.SetDefault(FollowerFalcoVersionsKey, DefaultFollower.FalcoVersions)

	err = viper.ReadInConfig()
	if errors.As(err, &viper.ConfigFileNotFoundError{}) {
		// If the config is not found, we create the file with the
		// already set up default values
		if err = os.MkdirAll(filepath.Dir(absolutePath), 0o700); err != nil {
			return fmt.Errorf("unable to create config directory: %w", err)
		}
		if err = viper.WriteConfigAs(path); err != nil {
			return fmt.Errorf("unable to write config file: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("unable to read config file: %w", err)
	}
	if err := viper.ReadInConfig(); err != nil {
		return fmt.Errorf("config: error reading config file: %w", err)
	}

	viper.SetEnvPrefix(EnvPrefix)

	// Environment variables can't have dashes in them, so bind them to their equivalent
	// keys with underscores. Also, consider nested keys by replacing dot with underscore.
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_", ".", "_"))

	// Bind to environment variables.
	viper.AutomaticEnv()

	return nil
}

// Indexes retrieves the indexes section of the config file.
func Indexes() ([]Index, error) {
	var indexes []Index

	if err := viper.UnmarshalKey(IndexesKey, &indexes, viper.DecodeHook(indexListHookFunc())); err != nil {
		return nil, fmt.Errorf("unable to get indexes: %w", err)
	}

	return indexes, nil
}

// indexListHookFunc returns a DecodeHookFunc that converts
// strings to string slices, when the target type is DotSeparatedStringList.
// when passed as env should be in the following format:
// "falcosecurity,https://falcosecurity.github.io/falcoctl/index.yaml;myindex,url"
func indexListHookFunc() mapstructure.DecodeHookFuncType {
	return func(f reflect.Type, t reflect.Type, data interface{}) (interface{}, error) {
		if f.Kind() != reflect.String && f.Kind() != reflect.Slice {
			return data, nil
		}

		if t != reflect.TypeOf([]Index{}) {
			return data, fmt.Errorf("unable to decode data since destination variable is not of type %T", []Index{})
		}

		switch f.Kind() {
		case reflect.String:
			tokens := strings.Split(data.(string), ";")
			indexes := make([]Index, len(tokens))
			for i, token := range tokens {
				values := strings.Split(token, ",")
				indexes[i] = Index{
					Name: values[0],
					URL:  values[1],
				}
			}
			return indexes, nil
		case reflect.Slice:
			var indexes []Index
			if err := mapstructure.WeakDecode(data, &indexes); err != nil {
				return err, nil
			}
			return indexes, nil
		default:
			return nil, nil
		}
	}
}

// BasicAuths retrieves the basicAuths section of the config file.
func BasicAuths() ([]BasicAuth, error) {
	var auths []BasicAuth

	if err := viper.UnmarshalKey(BasicAuthsKey, &auths, viper.DecodeHook(basicAuthListHookFunc())); err != nil {
		return nil, fmt.Errorf("unable to get basicAuths: %w", err)
	}

	return auths, nil
}

// basicAuthListHookFunc returns a DecodeHookFunc that converts
// strings to string slices, when the target type is DotSeparatedStringList.
// when passed as env should be in the following format:
// "registry,username,password;registry1,username1,password1".
func basicAuthListHookFunc() mapstructure.DecodeHookFuncType {
	return func(f reflect.Type, t reflect.Type, data interface{}) (interface{}, error) {
		if f.Kind() != reflect.String && f.Kind() != reflect.Slice {
			return data, nil
		}

		if t != reflect.TypeOf([]BasicAuth{}) {
			return data, fmt.Errorf("unable to decode data since destination variable is not of type %T", []BasicAuth{})
		}

		switch f.Kind() {
		case reflect.String:
			tokens := strings.Split(data.(string), ";")
			auths := make([]BasicAuth, len(tokens))
			for i, token := range tokens {
				values := strings.Split(token, ",")
				auths[i] = BasicAuth{
					Registry: values[0],
					User:     values[1],
					Password: values[2],
				}
			}
			return auths, nil
		case reflect.Slice:
			var auths []BasicAuth
			if err := mapstructure.WeakDecode(data, &auths); err != nil {
				return err, nil
			}
			return auths, nil
		default:
			return nil, nil
		}
	}
}

// OauthAuths retrieves the oauthAuths section of the config file.
func OauthAuths() ([]OauthAuth, error) {
	var auths []OauthAuth

	if err := viper.UnmarshalKey(OauthAuthsKey, &auths, viper.DecodeHook(oathAuthListHookFunc())); err != nil {
		return nil, fmt.Errorf("unable to get oauthAuths: %w", err)
	}

	return auths, nil
}

// oauthAuthListHookFunc returns a DecodeHookFunc that converts
// strings to string slices, when the target type is DotSeparatedStringList.
// when passed as env should be in the following format:
// "registry,clientID,clientSecret,tokenURL;registry1,clientID1,clientSecret1,tokenURL1".
func oathAuthListHookFunc() mapstructure.DecodeHookFuncType {
	return func(f reflect.Type, t reflect.Type, data interface{}) (interface{}, error) {
		if f.Kind() != reflect.String && f.Kind() != reflect.Slice {
			return data, nil
		}

		if t != reflect.TypeOf([]OauthAuth{}) {
			return data, fmt.Errorf("unable to decode data since destination variable is not of type %T", []OauthAuth{})
		}

		switch f.Kind() {
		case reflect.String:
			tokens := strings.Split(data.(string), ";")
			auths := make([]OauthAuth, len(tokens))
			for i, token := range tokens {
				values := strings.Split(token, ",")
				auths[i] = OauthAuth{
					Registry:     values[0],
					ClientID:     values[1],
					ClientSecret: values[2],
					TokenURL:     values[3],
				}
			}
			return auths, nil
		case reflect.Slice:
			var auths []OauthAuth
			if err := mapstructure.WeakDecode(data, &auths); err != nil {
				return err, nil
			}
			return auths, nil
		default:
			return nil, nil
		}
	}
}

// Follower retrieves the follower section of the config file.
func Follower() (Follow, error) {
	// with Follow we can just use nested keys.
	// env variables can just make use of ";" to separat
	artifacts := viper.GetStringSlice(FollowerArtifactsKey)
	if len(artifacts) == 1 { // in this case it might come from the env
		artifacts = strings.Split(artifacts[0], ";")
	}

	return Follow{
		Every:         viper.GetDuration(FollowerEveryKey),
		Artifacts:     artifacts,
		FalcoVersions: viper.GetString(FollowerFalcoVersionsKey),
		RulesfilesDir: viper.GetString(FollowerRulesfilesDirKey),
		PluginsDir:    viper.GetString(FollowerPluginsDirKey),
		WorkingDir:    viper.GetString(FollowerWorkingDirKey),
	}, nil
}

// Installer retrieves the installer section of the config file.
func Installer() (Install, error) {
	// with Install we can just use nested keys.
	// env variables can just make use of ";" to separat
	artifacts := viper.GetStringSlice(InstallerArtifactsKey)
	if len(artifacts) == 1 { // in this case it might come from the env
		artifacts = strings.Split(artifacts[0], ";")
	}

	return Install{
		Artifacts:     artifacts,
		RulesfilesDir: viper.GetString(InstallerRulesfilesDirKey),
		PluginsDir:    viper.GetString(InstallerPluginsDirKey),
	}, nil
}

// UpdateConfigFile is used to update a section of the config file.
// We create a brand new viper instance for doing it so that we are sure that modifications
// are scoped to the passed key with no side effects (e.g user forgot to unser one env variable for
// another config setting, avoid to mistakenly update it).
func UpdateConfigFile(key string, value interface{}, path string) error {
	v := viper.New()
	v.SetConfigName("config")

	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return err
	}

	v.AddConfigPath(filepath.Dir(absolutePath))
	v.SetConfigType("yaml")

	if err := v.ReadInConfig(); err != nil {
		return fmt.Errorf("config: error reading config file: %w", err)
	}

	v.Set(key, value)

	if err := v.WriteConfig(); err != nil {
		return fmt.Errorf("unable to set key %q to config file: %w", IndexesKey, err)
	}

	return nil
}

// FalcoVersions represent the map for Falco requirements
// In general, it should be a map[string]semver.Version, but given
// that we have fields like engine_version that are only numbers, we shoud be
// as muche generic as possible.
type FalcoVersions map[string]string
