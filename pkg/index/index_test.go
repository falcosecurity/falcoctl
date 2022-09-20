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
	"crypto/sha256"
	"fmt"
	"testing"

	"gopkg.in/yaml.v3"
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
