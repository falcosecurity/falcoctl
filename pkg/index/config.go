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

package index

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// ConfigEntry contains information about one of the index that were cached locally.
// TODO: add support for all the other fields.
type ConfigEntry struct {
	AddedTimestamp string `yaml:"added_timestamp"`
	// CaFile                string `yaml:"caFile"`
	// CertFile              string `yaml:"certFile"`
	// InsecureSkipTLSVerify string `yaml:"insecure_skip_tls_verify"`
	// KeyFile               string `yaml:"keyFile"`
	Name string `yaml:"name"`
	// PassCredentialsAll    string `yaml:"pass_credentials_all"`
	// Password              string `yaml:"password"`
	UpdatedTimestamp string `yaml:"updated_timestamp"`
	URL              string `yaml:"url"`
	// Username              string `yaml:"username"`
}

// Config aggregates the info about ConfigEntries.
type Config struct {
	Configs []ConfigEntry `yaml:"configs"`
}

// NewConfig loads an index config from a file.
func NewConfig(path string) (*Config, error) {
	var config Config
	file, err := os.ReadFile(filepath.Clean(path))
	if os.IsNotExist(err) {
		return &config, nil
	} else if err != nil {
		return nil, err
	}

	err = yaml.Unmarshal(file, &config)
	if err != nil {
		return nil, err
	}

	return &config, nil
}

// Add adds a new config to Config.
func (c *Config) Add(entry ConfigEntry) {
	c.Configs = append(c.Configs, entry)
}

// Upsert replaces the entry if already exists otherwise just appends it.
func (c *Config) Upsert(entry ConfigEntry) {
	for i, e := range c.Configs {
		if entry.Name == e.Name {
			c.Configs[i] = entry
			return
		}
	}
	c.Add(entry)
}

// Remove removes a config by name from an Config.
func (c *Config) Remove(name string) {
	for k, conf := range c.Configs {
		if conf.Name == name {
			c.Configs = append(c.Configs[:k], c.Configs[k+1:]...)
			break
		}
	}
}

// Get returns a pointer to an entry in a Config.
func (c *Config) Get(name string) *ConfigEntry {
	for k, conf := range c.Configs {
		if conf.Name == name {
			return &c.Configs[k]
		}
	}

	return nil
}

// Write writes a Config to disk.
func (c *Config) Write(path string) error {
	// Get dir path.
	dir, _ := filepath.Split(path)
	// Create directory if it does not exist.
	if _, err := os.Stat(dir); errors.Is(err, fs.ErrNotExist) {
		err = os.MkdirAll(dir, defaultDirPermissions) // #nosec G301 //we want 755 permissions
		if err != nil {
			return err
		}
	}

	data, err := yaml.Marshal(c)
	if err != nil {
		return err
	}

	err = os.WriteFile(path, data, defaultFilePermissions)
	if err != nil {
		return err
	}

	return nil
}
