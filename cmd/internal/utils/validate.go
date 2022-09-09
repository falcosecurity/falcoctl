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

package utils

import (
	"fmt"
	"strings"
)

// GetRegistryFromRef extracts the registry from a ref string.
func GetRegistryFromRef(ref string) (string, error) {
	index := strings.Index(ref, "/")
	if index <= 0 {
		return "", fmt.Errorf("cannot extract registry name from ref %q", ref)
	}

	return ref[0:index], nil
}
