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
	"regexp"
	"strings"
	"time"

	"github.com/docker/cli/cli/config"
	"github.com/docker/docker/pkg/homedir"
	"github.com/mitchellh/mapstructure"
	"github.com/spf13/viper"

	"github.com/falcosecurity/falcoctl/pkg/oci"
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
	// DefaultRegistryCredentialConfPath is the default path for the credential store configuration file.
	DefaultRegistryCredentialConfPath = filepath.Join(config.Dir(), "config.json")

	// Useful regexps for parsing.

	// SemicolonSeparatedRegexp is a regexp matching semi-colon separated values, without trailing separator.
	SemicolonSeparatedRegexp = regexp.MustCompile(`^([^;]+)(;[^;]+)*$`)
	// CommaSeparatedRegexp is a regexp matching comma separated values, without trailing separator.
	CommaSeparatedRegexp = regexp.MustCompile(`^([^,]+)(,[^,]+)*$`)
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

	// RegistryCredentialConfigKey is the Viper key for the credentials store path configuration.
	//#nosec G101 -- false positive
	RegistryCredentialConfigKey = "registry.creds.config"
	// RegistryAuthOauthKey is the Viper key for OAuth authentication configuration.
	RegistryAuthOauthKey = "registry.auth.oauth"
	// RegistryAuthBasicKey is the Viper key for basic authentication configuration.
	RegistryAuthBasicKey = "registry.auth.basic"
	// RegistryAuthGcpKey is the Viper key for gcp authentication configuration.
	RegistryAuthGcpKey = "registry.auth.gcp"
	// IndexesKey is the Viper key for indexes configuration.
	IndexesKey = "indexes"
	// ArtifactFollowEveryKey is the Viper key for follower "every" configuration.
	ArtifactFollowEveryKey = "artifact.follow.every"
	// ArtifactFollowCronKey is the Viper key for follower "cron" configuration.
	ArtifactFollowCronKey = "artifact.follow.cron"
	// ArtifactFollowRefsKey is the Viper key for follower "artifacts" configuration.
	ArtifactFollowRefsKey = "artifact.follow.refs"
	// ArtifactFollowFalcoVersionsKey is the Viper key for follower "falcoVersions" configuration.
	ArtifactFollowFalcoVersionsKey = "artifact.follow.falcoversions"
	// ArtifactFollowRulesfilesDirKey is the Viper key for follower "rulesFilesDir" configuration.
	ArtifactFollowRulesfilesDirKey = "artifact.follow.rulesfilesdir"
	// ArtifactFollowPluginsDirKey is the Viper key for follower "pluginsDir" configuration.
	ArtifactFollowPluginsDirKey = "artifact.follow.pluginsdir"
	// ArtifactFollowTmpDirKey is the Viper key for follower "pluginsDir" configuration.
	ArtifactFollowTmpDirKey = "artifact.follow.tmpdir"
	// ArtifactInstallArtifactsKey is the Viper key for installer "artifacts" configuration.
	ArtifactInstallArtifactsKey = "artifact.install.refs"
	// ArtifactInstallRulesfilesDirKey is the Viper key for follower "rulesFilesDir" configuration.
	ArtifactInstallRulesfilesDirKey = "artifact.install.rulesfilesdir"
	// ArtifactInstallPluginsDirKey is the Viper key for follower "pluginsDir" configuration.
	ArtifactInstallPluginsDirKey = "artifact.install.pluginsdir"
	// ArtifactInstallResolveDepsKey is the Viper key for installer "resolveDeps" configuration.
	ArtifactInstallResolveDepsKey = "artifact.install.resolveDeps"
	// ArtifactAllowedTypesKey is the Viper key for the whitelist of artifacts to be installed in the system.
	ArtifactAllowedTypesKey = "artifact.allowedTypes"
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

// GcpAuth represents a Gcp activation setting.
type GcpAuth struct {
	Registry string `mapstructure:"registry"`
}

// Follow represents the follower configuration.
type Follow struct {
	Every         time.Duration `mapstructure:"every"`
	Artifacts     []string      `mapstructure:"artifacts"`
	FalcoVersions string        `mapstructure:"falcoVersions"`
	RulesfilesDir string        `mapstructure:"rulesFilesDir"`
	PluginsDir    string        `mapstructure:"pluginsDir"`
	TmpDir        string        `mapstructure:"pluginsDir"`
}

// Install represents the installer configuration.
type Install struct {
	Artifacts     []string `mapstructure:"artifacts"`
	RulesfilesDir string   `mapstructure:"rulesFilesDir"`
	PluginsDir    string   `mapstructure:"pluginsDir"`
	ResolveDeps   bool     `mapstructure:"resolveDeps"`
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
}

// Load is used to load the config file.
func Load(path string) error {
	// we keep these for consistency, but not actually used
	// since we explicitly set the filepath later
	viper.SetConfigName("falcoctl")
	viper.SetConfigType("yaml")

	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return err
	}

	viper.SetConfigFile(absolutePath)

	// Set default index
	viper.SetDefault(IndexesKey, []Index{DefaultIndex})
	// Set default registry auth config path
	viper.SetDefault(RegistryCredentialConfigKey, DefaultRegistryCredentialConfPath)

	err = viper.ReadInConfig()
	if errors.As(err, &viper.ConfigFileNotFoundError{}) || os.IsNotExist(err) {
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
		return nil, fmt.Errorf("unable to get indexes from configuration: %w", err)
	}

	return indexes, nil
}

// Gcps retrieves the gcp auth section of the config file.
func Gcps() ([]GcpAuth, error) {
	var auths []GcpAuth

	if err := viper.UnmarshalKey(RegistryAuthGcpKey, &auths, viper.DecodeHook(gcpAuthListHookFunc())); err != nil {
		return nil, fmt.Errorf("unable to get gcpAuths: %w", err)
	}

	return auths, nil
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
			if !SemicolonSeparatedRegexp.MatchString(data.(string)) {
				return data, fmt.Errorf("env variable not correctly set, should match %q, got %q", SemicolonSeparatedRegexp.String(), data.(string))
			}
			tokens := strings.Split(data.(string), ";")
			indexes := make([]Index, len(tokens))
			for i, token := range tokens {
				if !CommaSeparatedRegexp.MatchString(token) {
					return data, fmt.Errorf("env variable not correctly set, should match %q, got %q", CommaSeparatedRegexp.String(), token)
				}

				values := strings.Split(token, ",")
				if len(values) != 2 {
					return data, fmt.Errorf("not valid token %q", token)
				}

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

// RegistryCredentialConfPath retrieves the path to the credential store configuration.
func RegistryCredentialConfPath() string {
	return viper.GetString(RegistryCredentialConfigKey)
}

// BasicAuths retrieves the basicAuths section of the config file.
func BasicAuths() ([]BasicAuth, error) {
	var auths []BasicAuth

	if err := viper.UnmarshalKey(RegistryAuthBasicKey, &auths, viper.DecodeHook(basicAuthListHookFunc())); err != nil {
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
			if !SemicolonSeparatedRegexp.MatchString(data.(string)) {
				return data, fmt.Errorf("env variable not correctly set, should match %q, got %q", SemicolonSeparatedRegexp.String(), data.(string))
			}
			tokens := strings.Split(data.(string), ";")
			auths := make([]BasicAuth, len(tokens))
			for i, token := range tokens {
				if !CommaSeparatedRegexp.MatchString(token) {
					return data, fmt.Errorf("env variable not correctly set, should match %q, got %q", CommaSeparatedRegexp.String(), token)
				}

				values := strings.Split(token, ",")
				if len(values) != 3 {
					return data, fmt.Errorf("not valid token %q", token)
				}

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

	if err := viper.UnmarshalKey(RegistryAuthOauthKey, &auths, viper.DecodeHook(oathAuthListHookFunc())); err != nil {
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
			if !SemicolonSeparatedRegexp.MatchString(data.(string)) {
				return data, fmt.Errorf("env variable not correctly set, should match %q, got %q", SemicolonSeparatedRegexp.String(), data.(string))
			}
			tokens := strings.Split(data.(string), ";")
			auths := make([]OauthAuth, len(tokens))
			for i, token := range tokens {
				if !CommaSeparatedRegexp.MatchString(token) {
					return data, fmt.Errorf("env variable not correctly set, should match %q, got %q", CommaSeparatedRegexp.String(), token)
				}
				values := strings.Split(token, ",")

				if len(values) != 4 {
					return data, fmt.Errorf("not valid token %q", token)
				}

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

// oauthAuthListHookFunc returns a DecodeHookFunc that converts
// strings to string slices, when the target type is DotSeparatedStringList.
// when passed as env should be in the following format:
// "registry;registry1".
func gcpAuthListHookFunc() mapstructure.DecodeHookFuncType {
	return func(f reflect.Type, t reflect.Type, data interface{}) (interface{}, error) {
		if f.Kind() != reflect.String && f.Kind() != reflect.Slice {
			return data, nil
		}

		if t != reflect.TypeOf([]GcpAuth{}) {
			return data, fmt.Errorf("unable to decode data since destination variable is not of type %T", []GcpAuth{})
		}

		switch f.Kind() {
		case reflect.String:
			if !SemicolonSeparatedRegexp.MatchString(data.(string)) {
				return data, fmt.Errorf("env variable not correctly set, should match %q, got %q", SemicolonSeparatedRegexp.String(), data.(string))
			}
			tokens := strings.Split(data.(string), ";")
			auths := make([]GcpAuth, len(tokens))
			for i, token := range tokens {
				auths[i] = GcpAuth{
					Registry: token,
				}
			}
			return auths, nil
		case reflect.Slice:
			var auths []GcpAuth
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
	artifacts := viper.GetStringSlice(ArtifactFollowRefsKey)
	if len(artifacts) == 1 { // in this case it might come from the env
		if !SemicolonSeparatedRegexp.MatchString(artifacts[0]) {
			return Follow{}, fmt.Errorf("env variable not correctly set, should match %q, got %q", SemicolonSeparatedRegexp.String(), artifacts[0])
		}
		artifacts = strings.Split(artifacts[0], ";")
	}

	return Follow{
		Every:         viper.GetDuration(ArtifactFollowEveryKey),
		Artifacts:     artifacts,
		FalcoVersions: viper.GetString(ArtifactFollowFalcoVersionsKey),
		RulesfilesDir: viper.GetString(ArtifactFollowRulesfilesDirKey),
		PluginsDir:    viper.GetString(ArtifactFollowPluginsDirKey),
		TmpDir:        viper.GetString(ArtifactFollowTmpDirKey),
	}, nil
}

// Installer retrieves the installer section of the config file.
func Installer() (Install, error) {
	// with Install we can just use nested keys.
	// env variables can just make use of ";" to separat
	artifacts := viper.GetStringSlice(ArtifactInstallArtifactsKey)
	if len(artifacts) == 1 { // in this case it might come from the env
		if !SemicolonSeparatedRegexp.MatchString(artifacts[0]) {
			return Install{}, fmt.Errorf("env variable not correctly set, should match %q, got %q", SemicolonSeparatedRegexp.String(), artifacts[0])
		}
		artifacts = strings.Split(artifacts[0], ";")
	}

	return Install{
		Artifacts:     artifacts,
		RulesfilesDir: viper.GetString(ArtifactInstallRulesfilesDirKey),
		PluginsDir:    viper.GetString(ArtifactInstallPluginsDirKey),
		ResolveDeps:   viper.GetBool(ArtifactInstallResolveDepsKey),
	}, nil
}

// ArtifactAllowedTypes retrieves the allowed types section of the config file.
func ArtifactAllowedTypes() (*oci.ArtifactTypeSlice, error) {
	allowedTypes := viper.GetStringSlice(ArtifactAllowedTypesKey)
	if len(allowedTypes) == 1 { // in this case it might come from the env
		if !CommaSeparatedRegexp.MatchString(allowedTypes[0]) {
			return nil, fmt.Errorf("env variable not correctly set, should match %q, got %q", SemicolonSeparatedRegexp.String(), allowedTypes[0])
		}
		allowedTypes = strings.Split(allowedTypes[0], ",")
	}

	var allowedArtifactTypes []oci.ArtifactType
	for _, t := range allowedTypes {
		var at oci.ArtifactType
		if err := at.Set(t); err != nil {
			return nil, fmt.Errorf("unrecognized artifact type in config: %q, %w", t, err)
		}

		allowedArtifactTypes = append(allowedArtifactTypes, at)
	}

	return &oci.ArtifactTypeSlice{
		Types:                allowedArtifactTypes,
		CommaSeparatedString: strings.Join(allowedTypes, ","),
	}, nil
}

// UpdateConfigFile is used to update a section of the config file.
// We create a brand new viper instance for doing it so that we are sure that modifications
// are scoped to the passed key with no side effects (e.g user forgot to unset one env variable for
// another config setting, avoid to mistakenly update it).
func UpdateConfigFile(key string, value interface{}, path string) error {
	v := viper.New()
	// we keep these for consistency, but not actually used
	// since we explicitly set the filepath later
	v.SetConfigName("falcoctl")
	v.SetConfigType("yaml")

	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return err
	}

	v.SetConfigFile(absolutePath)

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

// AddIndexes appends the provided indexes to a configuration file if not present.
func AddIndexes(indexes []Index, configFile string) error {
	var currIndexes []Index
	var err error

	// Retrieve the current indexes from configuration.
	if currIndexes, err = Indexes(); err != nil {
		return err
	}
	for i, idx := range indexes {
		if _, ok := findIndexInSlice(currIndexes, &indexes[i]); !ok {
			currIndexes = append(currIndexes, idx)
		}
	}

	if err := UpdateConfigFile(IndexesKey, currIndexes, configFile); err != nil {
		return fmt.Errorf("unable to update indexes list in the config file %q: %w", configFile, err)
	}

	return nil
}

// RemoveIndexes removes the index entries from a configuration file if any is found.
func RemoveIndexes(names []string, configFile string) error {
	var currIndexes []Index
	var err error

	// Retrieve the current indexes from configuration.
	if currIndexes, err = Indexes(); err != nil {
		return err
	}
	for _, name := range names {
		if i, ok := findIndexInSlice(currIndexes, &Index{Name: name}); ok {
			currIndexes = append(currIndexes[:i], currIndexes[i+1:]...)
		}
	}

	if err := UpdateConfigFile(IndexesKey, currIndexes, configFile); err != nil {
		return fmt.Errorf("unable to update indexes list in the config file %q: %w", configFile, err)
	}

	return nil
}

func findIndexInSlice(slice []Index, val *Index) (int, bool) {
	for i, item := range slice {
		if item.Name == val.Name {
			return i, true
		}
	}
	return -1, false
}

// AddGcp appends the provided gcps to a configuration file if not present.
func AddGcp(gcps []GcpAuth, configFile string) error {
	var currGcps []GcpAuth
	var err error

	// Retrieve the current gcps from configuration.
	if currGcps, err = Gcps(); err != nil {
		return err
	}
	for i, gcp := range gcps {
		if _, ok := findGcpInSlice(currGcps, &gcps[i]); !ok {
			currGcps = append(currGcps, gcp)
		}
	}

	if err := UpdateConfigFile(RegistryAuthGcpKey, currGcps, configFile); err != nil {
		return fmt.Errorf("unable to update gcps list in the config file %q: %w", configFile, err)
	}

	return nil
}

func findGcpInSlice(slice []GcpAuth, val *GcpAuth) (int, bool) {
	for i, item := range slice {
		if item.Registry == val.Registry {
			return i, true
		}
	}
	return -1, false
}
