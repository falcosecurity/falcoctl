// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The Falco Authors
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

package signature

import (
	"context"
	"testing"

	"github.com/falcosecurity/falcoctl/pkg/index/index"
)

func TestVerify_NilSignature(t *testing.T) {
	ctx := context.Background()
	err := Verify(ctx, "ghcr.io/test/image:latest", nil)
	if err != nil {
		t.Errorf("Verify with nil signature should return nil, got: %v", err)
	}
}

func TestVerify_NilCosign(t *testing.T) {
	ctx := context.Background()
	sig := &index.Signature{
		Cosign: nil,
	}
	err := Verify(ctx, "ghcr.io/test/image:latest", sig)
	if err != nil {
		t.Errorf("Verify with nil Cosign should return nil, got: %v", err)
	}
}

func TestVerify_EmptyRef(t *testing.T) {
	ctx := context.Background()
	sig := &index.Signature{
		Cosign: &index.CosignSignature{
			CertificateOidcIssuer: "https://token.actions.githubusercontent.com",
			CertificateIdentity:   "test@example.com",
		},
	}
	// Empty ref should fail during parsing
	err := Verify(ctx, "", sig)
	if err == nil {
		t.Error("Verify with empty ref should return an error")
	}
}

func TestVerify_InvalidRef(t *testing.T) {
	ctx := context.Background()
	sig := &index.Signature{
		Cosign: &index.CosignSignature{
			CertificateOidcIssuer: "https://token.actions.githubusercontent.com",
			CertificateIdentity:   "test@example.com",
		},
	}
	// Invalid ref should fail during parsing
	err := Verify(ctx, "not a valid ref!!!", sig)
	if err == nil {
		t.Error("Verify with invalid ref should return an error")
	}
}
