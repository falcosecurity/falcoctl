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

package oci

import (
	"context"
	"fmt"

	"github.com/blang/semver"
	"github.com/falcosecurity/falcoctl/pkg/oci/authn"
)

// Tags returns the list of all available tags of an artifact given a reference to a repository.
func Tags(ctx context.Context, ref string, client *authn.Client) ([]string, error) {
	repository, err := NewRepository(ref, WithClient(client))
	if err != nil {
		return nil, err
	}

	var result []string
	var tagRetriever = func(tags []string) error {
		result = tags
		return nil
	}

	err = repository.Tags(ctx, "", tagRetriever)
	if err != nil {
		return nil, err
	}

	result, err = sortTags(result)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func sortTags(tags []string) ([]string, error) {
	var parsedVersions []semver.Version
	var latest bool
	for _, t := range tags {
		if t == DefaultTag {
			latest = true
			continue
		}

		parsedVersion, err := semver.Parse(t)
		if err != nil {
			return nil, fmt.Errorf("cannot parse version %q", t)
		}

		parsedVersions = append(parsedVersions, parsedVersion)
	}

	semver.Sort(parsedVersions)

	var result []string
	for _, parsedVersion := range parsedVersions {
		result = append(result, parsedVersion.String())
	}

	if latest {
		result = append(result, DefaultTag)
	}

	return result, nil
}
