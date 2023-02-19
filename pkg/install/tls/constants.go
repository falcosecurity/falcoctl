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

package tls

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
