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
	"fmt"

	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"

	"github.com/falcosecurity/falcoctl/internal/cosign"
	"github.com/falcosecurity/falcoctl/pkg/index/index"
	"github.com/falcosecurity/falcoctl/pkg/oci/authn"
)

// Verify checks that a fully qualified reference is signed according to the parameters.
// It uses the same authentication sources as falcoctl's artifact operations.
func Verify(ctx context.Context, ref string, signature *index.Signature, plainHTTP bool) error {
	if signature == nil {
		// nothing to do
		return nil
	}

	if signature.Cosign == nil {
		// we currently only support cosign
		return nil
	}

	keychain, err := authn.NewKeychain()
	if err != nil {
		return fmt.Errorf("failed to create keychain: %w", err)
	}

	v := cosign.VerifyCommand{
		RegistryOptions: options.RegistryOptions{
			AllowHTTPRegistry: plainHTTP,
			AllowInsecure:     plainHTTP,
			Keychain:          keychain,
		},
		CertVerifyOptions: options.CertVerifyOptions{
			CertIdentity:         signature.Cosign.CertificateIdentity,
			CertIdentityRegexp:   signature.Cosign.CertificateIdentityRegexp,
			CertOidcIssuer:       signature.Cosign.CertificateOidcIssuer,
			CertOidcIssuerRegexp: signature.Cosign.CertificateOidcIssuerRegexp,
		},
		KeyRef:     signature.Cosign.KeyRef,
		IgnoreTlog: signature.Cosign.IgnoreTlog,
	}
	return v.DoVerify(ctx, []string{ref})
}
