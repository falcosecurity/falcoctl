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
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// IndexConfigEntry contains information about one of the index that were cached locally.
// TODO: add support for all the other fields.
type IndexConfigEntry struct {
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

// IndexConfig aggregates the info about IndexConfigEntries.
type IndexConfig struct {
	Configs []IndexConfigEntry `yaml:"configs"`
}

// NewIndexConfig loads an index config from a file.
func NewIndexConfig(path string) (*IndexConfig, error) {
	var indexConfig IndexConfig
	file, err := os.ReadFile(filepath.Clean(path))
	if os.IsNotExist(err) {
		return &indexConfig, nil
	} else if err != nil {
		return nil, err
	}

	err = yaml.Unmarshal(file, &indexConfig)
	if err != nil {
		return nil, err
	}

	return &indexConfig, nil
}

// Add adds a new config to IndexConfig.
func (ic *IndexConfig) Add(entry IndexConfigEntry) {
	ic.Configs = append(ic.Configs, entry)
}

// Remove removes a config by name from an IndexConfig.
func (ic *IndexConfig) Remove(name string) error {
	for k, conf := range ic.Configs {
		if conf.Name == name {
			ic.Configs = append(ic.Configs[:k], ic.Configs[k+1:]...)
			return nil
		}
	}

	return fmt.Errorf("cannot remove index %s: not found", name)
}

// Get returns a pointer to an entry in a IndexConfig.
func (ic *IndexConfig) Get(name string) (*IndexConfigEntry, error) {
	for k, conf := range ic.Configs {
		if conf.Name == name {
			return &ic.Configs[k], nil
		}
	}

	return nil, fmt.Errorf("not found")
}

// Write writes an IndexConfig to disk.
func (ic *IndexConfig) Write(path string) error {
	data, err := yaml.Marshal(ic)
	if err != nil {
		return err
	}

	err = os.WriteFile(path, data, writePermissions)
	if err != nil {
		return err
	}

	return nil
}
