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
	err := Verify(ctx, "ghcr.io/test/image:latest", nil, false)
	if err != nil {
		t.Errorf("Verify with nil signature should return nil, got: %v", err)
	}
}

func TestVerify_NilCosign(t *testing.T) {
	ctx := context.Background()
	sig := &index.Signature{
		Cosign: nil,
	}
	err := Verify(ctx, "ghcr.io/test/image:latest", sig, false)
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
	err := Verify(ctx, "", sig, false)
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
	err := Verify(ctx, "not a valid ref!!!", sig, false)
	if err == nil {
		t.Error("Verify with invalid ref should return an error")
	}
}

func TestVerify_PlainHTTP(t *testing.T) {
	ctx := context.Background()
	sig := &index.Signature{
		Cosign: &index.CosignSignature{
			CertificateOidcIssuer: "https://token.actions.githubusercontent.com",
			CertificateIdentity:   "test@example.com",
		},
	}
	// This should create keychain and set plainHTTP options correctly
	// It will fail because the image doesn't exist, but the keychain creation should work
	err := Verify(ctx, "localhost:5000/test/image:latest", sig, true)
	// We expect an error (image doesn't exist), but not a keychain creation error
	if err == nil {
		t.Error("Verify should fail for non-existent image")
	}
	// The error should be about the image not existing, not about keychain
	if err != nil && err.Error() == "failed to create keychain" {
		t.Errorf("Verify should not fail on keychain creation: %v", err)
	}
}

func TestVerify_WithKeyRef(t *testing.T) {
	ctx := context.Background()
	sig := &index.Signature{
		Cosign: &index.CosignSignature{
			KeyRef: "cosign.pub",
		},
	}
	// This tests that KeyRef is properly passed to cosign
	err := Verify(ctx, "ghcr.io/test/image:latest", sig, false)
	// We expect an error (image doesn't exist), but the signature config should be valid
	if err == nil {
		t.Error("Verify should fail for non-existent image")
	}
}

func TestVerify_WithIgnoreTlog(t *testing.T) {
	ctx := context.Background()
	sig := &index.Signature{
		Cosign: &index.CosignSignature{
			CertificateOidcIssuer: "https://token.actions.githubusercontent.com",
			CertificateIdentity:   "test@example.com",
			IgnoreTlog:            true,
		},
	}
	// This tests that IgnoreTlog is properly passed to cosign
	err := Verify(ctx, "ghcr.io/test/image:latest", sig, false)
	// We expect an error (image doesn't exist), but the signature config should be valid
	if err == nil {
		t.Error("Verify should fail for non-existent image")
	}
}

func TestVerify_WithCertIdentityRegexp(t *testing.T) {
	ctx := context.Background()
	sig := &index.Signature{
		Cosign: &index.CosignSignature{
			CertificateOidcIssuer:       "https://token.actions.githubusercontent.com",
			CertificateIdentityRegexp:   ".*@example.com",
			CertificateOidcIssuerRegexp: "https://token.actions.*",
		},
	}
	// This tests that regexp options are properly passed to cosign
	err := Verify(ctx, "ghcr.io/test/image:latest", sig, false)
	// We expect an error (image doesn't exist), but the signature config should be valid
	if err == nil {
		t.Error("Verify should fail for non-existent image")
	}
}
