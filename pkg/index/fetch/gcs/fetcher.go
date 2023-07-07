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
	"context"
	"fmt"
	"io"

	"cloud.google.com/go/storage"
	"google.golang.org/api/option"

	"github.com/falcosecurity/falcoctl/pkg/index/config"
)

const gcsReadOnlyScope = "https://www.googleapis.com/auth/devstorage.read_only"

// Fetch fetches the raw index file from a GCS object.
func Fetch(ctx context.Context, conf *config.Entry) ([]byte, error) {
	o, err := gcsObjectFromURI(conf.URL)
	if err != nil {
		return nil, err
	}

	// defaults to using application default credentials when needed
	c, err := storage.NewClient(ctx, option.WithScopes(gcsReadOnlyScope))
	if err != nil {
		return nil, fmt.Errorf("unable to create GCS client: %w", err)
	}

	reader, err := c.Bucket(o.Bucket).Object(o.Object).NewReader(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to create GCS object reader: %w", err)
	}

	res, err := io.ReadAll(reader)
	closeErr := reader.Close()
	if closeErr != nil {
		if err != nil {
			err = fmt.Errorf("%w, %w", err, closeErr)
		} else {
			err = closeErr
		}
	}
	if err != nil {
		return nil, fmt.Errorf("error reading GCS object: %w", err)
	}

	return res, nil
}
