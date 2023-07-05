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

package sign

import (
	"context"

	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"

	"github.com/falcosecurity/falcoctl/internal/cosign"
	"github.com/falcosecurity/falcoctl/pkg/index"
)

// VerifySignature checks that a fully qualified reference is signed according to the parameters.
func VerifySignature(ctx context.Context, ref string, signature *index.Signature) error {
	if signature == nil {
		// nothing to do
		return nil
	}

	if signature.Cosign == nil {
		// we currently only support cosign
		return nil
	}

	v := cosign.VerifyCommand{
		CertVerifyOptions: options.CertVerifyOptions{
			CertIdentity:         signature.Cosign.CertificateIdentity,
			CertIdentityRegexp:   signature.Cosign.CertificateIdentityRegexp,
			CertOidcIssuer:       signature.Cosign.CertificateOidcIssuer,
			CertOidcIssuerRegexp: signature.Cosign.CertificateOidcIssuerRegexp,
		},
	}
	return v.DoVerify(ctx, []string{ref})
}
