package tls

// Certs material filenames
const (

	// ServerKey is the default filename of the client private key.
	ServerKey = "server.key"

	// ClientKey is the default filename of the client private key.
	ClientKey = "client.key"

	// CAKey is the default filename of the certificate authority private key.
	CAKey = "ca.key"

	// CACert is the default filename of the certificate authority certificate.
	CACert = "ca.crt"

	// ServerCert is the default filename of the server certificate.
	ServerCert = "server.crt"

	// ClientCert is the default filename of the client certificate.
	ClientCert = "client.crt"

	// DefaultRSABits is the default bit size to generate an RSA keypair.
	DefaultRSABits int = 4096

	// DefaultAlgorithm is the default digital signature algorithm.
	DefaultAlgorithm = RSAType

	// ECDSAType represents the ECDSA DSA algorithm.
	ECDSAType DSAType = "ecdsa"

	// RSAType represents the RSA DSA algorithm.
	RSAType DSAType = "rsa"

	// RSADefaultSize is the default size of the RSA-signed key.
	RSADefaultSize = 2048

	// RSAPrivateKeyPEMHeader is the header of PEM-encoded RSA-signed keys.
	RSAPrivateKeyPEMHeader = "RSA PRIVATE KEY"

	// ECDSAPrivateKeyPEMHeader is the header of PEM-encoded ECDSA-signed keys.
	ECDSAPrivateKeyPEMHeader = "ECDSA PRIVATE KEY"

	// CertificatePEMHeader is the header of PEM-encoded x509 certificate.
	CertificatePEMHeader = "CERTIFICATE"
)

var certsFilenames = []string{
	ServerKey,
	ClientKey,
	CAKey,
	CACert,
	ServerCert,
	ClientCert,
}
