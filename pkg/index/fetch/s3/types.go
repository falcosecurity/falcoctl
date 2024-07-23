// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 The Falco Authors
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

package s3

import (
	"fmt"
	"net/url"
	"strings"
)

const s3Scheme = "s3"

// s3Object represents an S3 object with its bucket and key.
type s3Object struct {
	Bucket string
	Key    string
}

// s3ObjectFromURI parses S3 URIs (s3://<bucket>/<object>) and returns a s3Object.
func s3ObjectFromURI(uri string) (*s3Object, error) {
	parsedURI, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("unable to parse URI: %w", err)
	}

	if !strings.EqualFold(parsedURI.Scheme, s3Scheme) {
		return nil, fmt.Errorf("invalid S3 URI: scheme should be '%s' but got '%s'", s3Scheme, parsedURI.Scheme)
	}

	if parsedURI.Host == "" {
		return nil, fmt.Errorf("invalid S3 URI: missing bucket name")
	}

	if parsedURI.Path == "" {
		return nil, fmt.Errorf("invalid S3 URI: missing object name")
	}

	return &s3Object{
		Bucket: parsedURI.Host,
		Key:    parsedURI.Path[1:], // Remove the leading slash
	}, nil
}
