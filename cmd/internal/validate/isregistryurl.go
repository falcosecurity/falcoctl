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

package validate

import (
	"fmt"
	"net/url"

	"github.com/go-playground/validator/v10"
)

func isRegistryURL(fl validator.FieldLevel) bool {
	myUrl := fl.Field()
	_, err := url.ParseRequestURI(myUrl.String())
	if err != nil {
		panic(fmt.Sprintf("Bad field type %T", myUrl.Interface()))
	}
	return true
}
