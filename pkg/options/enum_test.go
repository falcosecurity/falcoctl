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

package options

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Enum", func() {
	var (
		allowed  = []string{"val1", "val2", "val3"}
		defValue = "val1"
		enum     *Enum
	)

	BeforeEach(func() {
		enum = NewEnum(allowed, defValue)
	})

	JustAfterEach(func() {
		enum = nil
	})

	Context("NewEnum Func", func() {
		It("should return a not nil struct", func() {
			Expect(enum).ShouldNot(BeNil())
		})

		It("should set the default values", func() {
			Expect(enum.value).Should(Equal(defValue))
		})

		It("should set the allowed values", func() {
			Expect(enum.allowed).Should(Equal(allowed))
		})
	})

	Context("Set Func", func() {
		var val string
		var err error
		newVal := "val2"
		newValWrong := "WrongVal"

		JustBeforeEach(func() {
			err = enum.Set(val)
		})

		Context("Setting an allowed value", func() {
			BeforeEach(func() {
				val = newVal
			})

			It("Should set the correct val", func() {
				Expect(err).ShouldNot(HaveOccurred())
				Expect(enum.value).Should(Equal(newVal))
			})
		})

		Context("Setting a not allowed value", func() {
			BeforeEach(func() {
				val = newValWrong
			})

			It("Should error", func() {
				Expect(err).Should(HaveOccurred())
			})
		})
	})

	Context("String Func", func() {
		It("Should return the setted value", func() {
			Expect(enum.String()).Should(Equal(defValue))
		})
	})

	Context("Type Func", func() {
		It("Should return the string type", func() {
			Expect(enum.Type()).Should(Equal("string"))
		})
	})

})
