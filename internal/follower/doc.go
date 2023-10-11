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

// Package follower defines the Follower type. It is used to track a specific artifact version denoted by its tag.
// Periodically it checks if a new version has been pushed and if so pulls and installs it in a given directory.
// Each Follower can track only one artifact, if you need to track multiple artiacts then instantiate a follower for each one.
package follower
