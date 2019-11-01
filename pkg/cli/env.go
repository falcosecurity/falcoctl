/*
Copyright © 2019 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package cli

import (
	"os"
	"strconv"
)

// GetEnvWithDefault get environment variable with fallback on a default value
func GetEnvWithDefault(env string, def string) string {
	val := os.Getenv(env)
	if val == "" {
		return def
	}
	return val
}

// GetBoolEnvWithDefault get a bool environment variable with a bool fallback on a default value
func GetBoolEnvWithDefault(env string, def bool) bool {
	val := os.Getenv(env)
	if val == "" {
		return def
	}
	b, err := strconv.ParseBool(val)
	if err != nil {
		return def
	}
	return b
}
