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

package gcs

import (
	"fmt"
	"net/url"
	"strings"
)

const gcsScheme = "gs"

type gcsObject struct {
	Bucket string
	Object string
}

// gcsObjectFromURI parses GCS URIs (gs://<bucket>/<object>) and returns a gcsObject.
func gcsObjectFromURI(uri string) (*gcsObject, error) {
	parsedURI, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("unable to parse URI: %w", err)
	}

	if !strings.EqualFold(parsedURI.Scheme, gcsScheme) {
		return nil, fmt.Errorf("invalid GCS URI: scheme should be '%s' but got '%s'", gcsScheme, parsedURI.Scheme)
	}

	if parsedURI.Host == "" {
		return nil, fmt.Errorf("invalid GCS URI: missing bucket name")
	}

	if parsedURI.Path == "" {
		return nil, fmt.Errorf("invalid GCS URI: missing object name")
	}

	return &gcsObject{
		Bucket: parsedURI.Host,
		Object: parsedURI.Path[1:],
	}, nil
}
