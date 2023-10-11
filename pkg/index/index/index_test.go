// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2023 The Falco Authors
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
	"crypto/sha256"
	"fmt"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/falcosecurity/falcoctl/pkg/index/config"
)

const expectedIndexNormalized = `- name: baz
  type: ""
  registry: ""
  repository: ""
  description: ""
  home: ""
  keywords: []
  license: ""
  maintainers: []
  sources: []
- name: foo
  type: ""
  registry: ""
  repository: ""
  description: ""
  home: ""
  keywords: []
  license: ""
  maintainers: []
  sources: []
`

func TestUpsert(t *testing.T) {
	i := New("name")

	i.Upsert(&Entry{
		Name: "foo",
		Type: "plugin",
	})

	if len(i.Entries) != 1 {
		t.Errorf("error upsert in index")
	}

	i.Upsert(&Entry{
		Name: "foo",
		Type: "bar",
	})

	entry, ok := i.EntryByName("foo")
	if !ok {
		t.Errorf("cannot retrieve entry by name")
	}

	if entry.Type != "bar" {
		t.Errorf("upsert didn't modify the entry")
	}
}

func TestRemove(t *testing.T) {
	i := New("name")

	entry := &Entry{
		Name: "foo",
		Type: "plugin",
	}

	i.Upsert(entry)

	if err := i.Remove(entry); err != nil {
		t.Error(err)
	}

	if len(i.Entries) != 0 {
		t.Errorf("error remove from index")
	}
}

func TestMerge(t *testing.T) {
	i1 := New("index1")
	i2 := New("index2")

	i1.Upsert(&Entry{
		Name: "cloudtrail",
		Type: "plugin",
	})

	i1.Upsert(&Entry{
		Name: "github",
		Type: "plugin",
	})

	i2.Upsert(&Entry{
		Name: "okta",
		Type: "plugin",
	})

	mergedIndex := NewMergedIndexes()
	mergedIndex.Merge(i1, i2)

	if len(mergedIndex.Entries) != 3 {
		t.Errorf("Indexes not properly merged")
	}

	cloudtrail, ok := mergedIndex.EntryByName("cloudtrail")
	if !ok {
		t.Errorf("cannot retrieve entry from merged index")
	}

	okta, ok := mergedIndex.EntryByName("okta")
	if !ok {
		t.Errorf("cannot retrieve entry from merged index")
	}

	if mergedIndex.IndexByEntry(cloudtrail).Name != "index1" ||
		mergedIndex.IndexByEntry(okta).Name != "index2" {
		t.Errorf("cannot correctly retrieve original index from merged index")
	}
}

func TestSearchByKeywords(t *testing.T) {
	i := New("name")

	i.Upsert(&Entry{
		Name: "cloudtrail",
		Type: "plugin",
	})

	// Test exact name.
	exactName := i.SearchByKeywords(1, "cloudtrail")
	if len(exactName) != 1 {
		t.Errorf("error in SearchByKeywords, expected to find one exact match")
	}

	// Test mistyped name.
	mistypedName := i.SearchByKeywords(0.8, "cloudtrailz")
	if len(mistypedName) != 1 {
		t.Errorf("error in SearchByKeywords, expected to find a match even if keyword is mistyped")
	}

	// Test with perfect match on keyword.
	i.Upsert(&Entry{
		Name:     "github",
		Keywords: []string{"webhook", "security", "audit"},
	})
	perfectKeyword := i.SearchByKeywords(1, "webhook")
	if len(perfectKeyword) != 1 {
		t.Errorf("error in SearchByKeywords, expected to find a perfect match with keyword")
	}

	// Test partial match
	partialKeywordMatch := i.SearchByKeywords(1, "web")
	if len(partialKeywordMatch) != 1 {
		t.Errorf("error in SearchByKeywords, expected to find a partial match with keyword")
	}

	// Check that no duplicates are returned
	noDuplicates := i.SearchByKeywords(1, "github", "webhook")
	if len(noDuplicates) != 1 {
		t.Errorf("error in SearchByKeywords, not expecting duplicates")
	}
}

func TestNormalize(t *testing.T) {
	i := Index{
		Name:        "name",
		Entries:     make([]*Entry, 0),
		entryByName: make(map[string]*Entry),
	}

	i.Upsert(&Entry{
		Name: "foo",
	})
	i.Upsert(&Entry{
		Name: "baz",
	})

	if err := i.Normalize(); err != nil {
		t.Error(err)
	}

	indexBytes, err := yaml.Marshal(i.Entries)
	if err != nil {
		t.Error(err)
	}

	expectedHash := sha256.New()
	_, err = expectedHash.Write([]byte(expectedIndexNormalized))
	if err != nil {
		t.Error(err)
	}

	hash := sha256.New()
	_, err = hash.Write(indexBytes)
	if err != nil {
		t.Error(err)
	}

	if fmt.Sprintf("%x", hash.Sum(nil)) != fmt.Sprintf("%x", expectedHash.Sum(nil)) {
		t.Error("Index not normalized as expected", string(indexBytes))
	}
}

func TestConfig(t *testing.T) {
	c, err := config.New("../testdata/config.yaml")
	if err != nil {
		t.Error(err)
	}

	c.Remove("test")
	for _, item := range c.Configs {
		if item.Name == "test" {
			t.Error(fmt.Errorf("entry \"test\" should have been removed"))
		}
	}

	c.Add(&config.Entry{
		Name: "test",
		URL:  "https://test.com/index.yaml",
	})

	entry := c.Get("test")
	if entry == nil {
		t.Error(fmt.Errorf("entry \"test\" not found"))
	}
}
