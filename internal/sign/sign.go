package sign

import (
	"context"

	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"

	"github.com/falcosecurity/falcoctl/internal/cosign"
	"github.com/falcosecurity/falcoctl/pkg/index"
)

func VerifySignature(ref string, signature *index.Signature) error {
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
	return v.DoVerify(context.Background(), []string{ref})
}
