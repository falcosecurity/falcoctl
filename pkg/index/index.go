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
	"io"
	"net/http"
	"os"

	"gopkg.in/yaml.v3"
)

// IndexEntry describe an entry of the index stored remotely and cached locally.
type IndexEntry struct {
	Description string   `yaml:"description"`
	Home        string   `yaml:"home"`
	Keywords    []string `yaml:"keywords"`
	License     string   `yaml:"license"`
	Maintainers []struct {
		Email string `yaml:"email"`
		Name  string `yaml:"name"`
	} `yaml:"maintainers"`
	Name       string   `yaml:"name"`
	Registry   string   `yaml:"registry"`
	Repository string   `yaml:"repository"`
	Sources    []string `yaml:"sources"`
	Type       string   `yaml:"type"`
}

type Index struct {
	Name        string
	Filename    string
	Config      *IndexConfig
	Entries     []IndexEntry
	entryByName map[string]*IndexEntry
}

// NewIndex loads an index from a file.
func NewIndex(path string) (*Index, error) {
	indexBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read file %s: %w", path, err)
	}

	var index Index
	if err = yaml.Unmarshal(indexBytes, &index); err != nil {
		return nil, fmt.Errorf("cannot unmarshal index: %w", err)
	}

	return &index, nil
}

// GetIndex retrieves a remote index using its URL.
func GetIndex(url string) (*Index, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}

	// Check server response
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("cannot download index, bad response status: %s", resp.Status)
	}
	defer resp.Body.Close()

	bytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("cannot read bytes from response body: %w", err)
	}

	var index Index
	if err := yaml.Unmarshal(bytes, &index.Entries); err != nil {
		return nil, fmt.Errorf("cannot unmarshal index: %w", err)
	}

	return &index, nil
}

func (i *Index) Add(entry *IndexEntry) {
	i.Entries = append(i.Entries, *entry)
}

func (i *Index) Remove(name string) error {
	for k, entry := range i.Entries {
		if entry.Name == name {
			i.Entries = append(i.Entries[:k], i.Entries[k+1:]...)
			return nil
		}
	}

	return fmt.Errorf("cannot remove %s: not found", name)
}

func (i *Index) Write(path string) error {
	indexBytes, err := yaml.Marshal(i.Entries)
	if err != nil {
		return fmt.Errorf("cannot marshal index: %w", err)
	}

	if err = os.WriteFile(path, indexBytes, 0600); err != nil {
		return fmt.Errorf("cannot write index to file: %w", err)
	}

	return nil
}

func Merge(indexes ...Index) (*Index, error) {

	return nil, nil
}
