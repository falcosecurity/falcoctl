/*
Copyright © 2019 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package tls

import (
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/kris-nova/logger"

	"github.com/spacemonkeygo/openssl"
)

const (
	DefaultRSABytes   int = 4096
	DefaultServerKey      = "server.key"
	DefaultClientKey      = "client.key"
	DefaultCAKey          = "ca.key"
	DefaultServerCSR      = "server.csr"
	DefaultClientCSR      = "client.csr"
	DefaultCACert         = "ca.crt"
	DefaultServerCert     = "server.crt"
	DefaultClientCert     = "client.crt"
)

var (
	DefaultX509SubjectFields = map[string]string{
		"ST": "US",
		"L":  "San Francisco",
		"OU": "Default",
	}
)

type GRPCTLS struct {
	RSABytes      int
	Country       string
	Organization  string
	CommonName    string
	Expiration    time.Duration
	SubjectFields map[string]string
	CACert        *openssl.Certificate
	ServerCert    *openssl.Certificate
	ServerCSR     *openssl.Certificate
	ClientCert    *openssl.Certificate
	ClientCSR     *openssl.Certificate
	CAKey         openssl.PrivateKey
	ServerKey     openssl.PrivateKey
	ClientKey     openssl.PrivateKey
}

// GRPCTLSGenerator is used to init a new TLS Generator for Falco
func GRPCTLSGenerator(country, organization, name string, days int) *GRPCTLS {
	return &GRPCTLS{
		RSABytes:      DefaultRSABytes,
		Country:       country,
		Organization:  organization,
		CommonName:    name,
		Expiration:    time.Duration(days) * 24 * time.Hour,
		SubjectFields: DefaultX509SubjectFields,
	}
}

// Generate is used to first generate TLS material in memory.
func (g *GRPCTLS) Generate() error {
	i64 := &big.Int{}
	i64.SetInt64(01)

	//$ openssl genrsa -passout pass:1234 -des3 -out ca.key 4096
	caKey, err := openssl.GenerateRSAKey(g.RSABytes)
	if err != nil {
		return fmt.Errorf("unable to generate RSA key: %v", err)
	}
	//$ openssl req -passin pass:1234 -new -x509 -days 365 -key ca.key -out ca.crt -subj  "/C=SP/ST=Italy/L=Ornavasso/O=Test/OU=Test/CN=Root CA"
	certificateSigningInfo := &openssl.CertificateInfo{
		Serial:       i64,
		Issued:       0,
		Expires:      g.Expiration,
		Country:      g.Country,
		Organization: g.Organization,
		CommonName:   "Root CA",
	}
	caCert, err := openssl.NewCertificate(certificateSigningInfo, caKey)
	if err != nil {
		return fmt.Errorf("unable to generate new signing certificate: %v", err)
	}
	name := &openssl.Name{}
	name.AddTextEntries(g.SubjectFields)
	caCert.SetSubjectName(name)
	caCert.SetVersion(openssl.X509_V3)
	if err := caCert.AddExtensions(map[openssl.NID]string{
		openssl.NID_basic_constraints:      "critical,CA:TRUE",
		openssl.NID_key_usage:              "critical,keyCertSign,cRLSign",
		openssl.NID_subject_key_identifier: "hash",
		openssl.NID_netscape_cert_type:     "sslCA",
	}); err != nil {
		return fmt.Errorf("unable to add caCert extensions: %v", err)
	}
	err = caCert.Sign(caKey, openssl.EVP_SHA256)
	if err != nil {
		return fmt.Errorf("unable to sign caCert: %v", err)
	}

	//$ openssl genrsa -passout pass:1234 -des3 -out server.key 4096
	serverKey, err := openssl.GenerateRSAKey(g.RSABytes)
	if err != nil {
		return fmt.Errorf("unable to generate server RSA key: %v", err)
	}
	//$ openssl req -passin pass:1234 -new -key server.key -out server.csr -subj  "/C=SP/ST=Italy/L=Ornavasso/O=Test/OU=Server/CN=localhost"
	serverCertificateSigningInfo := &openssl.CertificateInfo{
		Serial:       i64,
		Issued:       0,
		Expires:      g.Expiration,
		Country:      g.Country,
		Organization: g.Organization,
		CommonName:   g.CommonName,
	}
	serverCSR, err := openssl.NewCertificate(serverCertificateSigningInfo, serverKey)
	if err != nil {
		return fmt.Errorf("unable to generate new signing certificate: %v", err)
	}
	serverName := &openssl.Name{}
	serverName.AddTextEntries(g.SubjectFields)
	serverCSR.SetSubjectName(serverName)
	serverCSR.SetVersion(openssl.X509_V3)
	err = serverCSR.Sign(serverKey, openssl.EVP_SHA256)
	if err != nil {
		return fmt.Errorf("unable to sign serverCSR: %v", err)
	}
	serverCASigningInfo := &openssl.CertificateInfo{
		Serial:       i64,
		Issued:       0,
		Expires:      g.Expiration,
		Country:      g.Country,
		Organization: g.Organization,
		CommonName:   g.CommonName,
	}
	//$ openssl x509 -req -passin pass:1234 -days 365 -in server.csr -CA ca.crt -CAkey ca.key -set_serial 01 -out server.crt
	serverCert, err := openssl.NewCertificate(serverCASigningInfo, serverKey)
	if err != nil {
		return fmt.Errorf("unable to create new server cert: %v", err)
	}
	serverCert.SetIssuer(caCert)
	err = serverCert.Sign(serverKey, openssl.EVP_SHA256)
	if err != nil {
		return fmt.Errorf("unable to sign serverCert: %v", err)
	}
	err = serverCert.Sign(caKey, openssl.EVP_SHA256)
	if err != nil {
		return fmt.Errorf("unable to sign serverCert: %v", err)
	}

	//$ openssl genrsa -passout pass:1234 -des3 -out client.key 4096
	clientKey, err := openssl.GenerateRSAKey(g.RSABytes)
	if err != nil {
		return fmt.Errorf("unable to generate client RSA key: %v", err)
	}
	// $ openssl req -passin pass:1234 -new -key client.key -out client.csr -subj  "/C=SP/ST=Italy/L=Ornavasso/O=Test/OU=Client/CN=localhost"
	clientCertificateSigningInfo := &openssl.CertificateInfo{
		Serial:       i64,
		Issued:       0,
		Expires:      g.Expiration,
		Country:      g.Country,
		Organization: g.Organization,
		CommonName:   g.CommonName,
	}
	clientCSR, err := openssl.NewCertificate(clientCertificateSigningInfo, clientKey)
	if err != nil {
		return fmt.Errorf("unable to generate new signing certificate: %v", err)
	}
	clientName := &openssl.Name{}
	clientName.AddTextEntries(g.SubjectFields)
	clientCSR.SetSubjectName(clientName)
	clientCSR.SetVersion(openssl.X509_V3)
	err = clientCSR.Sign(clientKey, openssl.EVP_SHA256)
	if err != nil {
		return fmt.Errorf("unable to sign clientCSR: %v", err)
	}
	clientCASigningInfo := &openssl.CertificateInfo{
		Serial:       i64,
		Issued:       0,
		Expires:      g.Expiration,
		Country:      g.Country,
		Organization: g.Organization,
		CommonName:   g.CommonName,
	}
	// $ openssl x509 -passin pass:1234 -req -days 365 -in client.csr -CA ca.crt -CAkey ca.key -set_serial 01 -out client.crt
	clientCert, err := openssl.NewCertificate(clientCASigningInfo, clientKey)
	if err != nil {
		return fmt.Errorf("unable to create new client cert: %v", err)
	}
	clientCert.SetIssuer(caCert)
	err = clientCert.Sign(clientKey, openssl.EVP_SHA256)
	if err != nil {
		return fmt.Errorf("unable to sign clientCert: %v", err)
	}
	err = clientCert.Sign(caKey, openssl.EVP_SHA256)
	if err != nil {
		return fmt.Errorf("unable to sign clientCert: %v", err)
	}

	// Cache TLS Cert material
	g.CACert = caCert
	g.ServerCert = serverCert
	g.ServerCSR = serverCSR
	g.ClientCert = clientCert
	g.ClientCSR = clientCSR
	g.CAKey = caKey
	g.ServerKey = serverKey
	g.ClientKey = clientKey

	return nil
}

// FlushToDisk is used to persist the cert material from a GRPCTLS to disk given a path.
func (g *GRPCTLS) FlushToDisk(path string) error {
	p, err := satisfyDir(path)
	if err != nil {
		return fmt.Errorf("invalid path: %v", err)
	}
	path = p

	// --- Write server.crt
	serverCert, err := g.ServerCert.MarshalPEM()
	if err != nil {
		return fmt.Errorf("unable to marshal PEM data for serverCRT: %v", err)
	}
	f := filepath.Join(path, DefaultServerCert)
	logger.Always("Writing: %s", f)
	err = ioutil.WriteFile(f, serverCert, 0600)
	if err != nil {
		return fmt.Errorf("error writing [%s]: %v", f, err)
	}

	// --- Write client.crt
	clientCert, err := g.ClientCert.MarshalPEM()
	if err != nil {
		return fmt.Errorf("unable to marshal PEM data for serverCRT: %v", err)
	}
	f = filepath.Join(path, DefaultClientCert)
	logger.Always("Writing: %s", f)
	err = ioutil.WriteFile(f, clientCert, 0600)
	if err != nil {
		return fmt.Errorf("error writing [%s]: %v", f, err)
	}

	// --- Write ca.crt
	caCert, err := g.CACert.MarshalPEM()
	if err != nil {
		return fmt.Errorf("unable to marshal PEM data for caCert: %v", err)
	}
	f = filepath.Join(path, DefaultCACert)
	logger.Always("Writing: %s", f)
	err = ioutil.WriteFile(f, caCert, 0600)
	if err != nil {
		return fmt.Errorf("error writing [%s]: %v", f, err)
	}

	// --- Write server.csr
	serverCSR, err := g.ServerCSR.MarshalPEM()
	if err != nil {
		return fmt.Errorf("unable to marshal PEM data for serverCSR: %v", err)
	}
	f = filepath.Join(path, DefaultServerCSR)
	logger.Always("Writing: %s", f)
	err = ioutil.WriteFile(f, serverCSR, 0600)
	if err != nil {
		return fmt.Errorf("error writing [%s]: %v", f, err)
	}

	// --- Write client.csr
	clientCSR, err := g.ClientCSR.MarshalPEM()
	if err != nil {
		return fmt.Errorf("unable to marshal PEM data for clientCSR: %v", err)
	}
	f = filepath.Join(path, DefaultClientCSR)
	logger.Always("Writing: %s", f)
	err = ioutil.WriteFile(f, clientCSR, 0600)
	if err != nil {
		return fmt.Errorf("error writing [%s]: %v", f, err)
	}

	// --- Write ca.key
	caKey, err := g.CAKey.MarshalPKCS1PrivateKeyPEM()
	if err != nil {
		return fmt.Errorf("unable to marshal PEM data for caKey: %v", err)
	}
	f = filepath.Join(path, DefaultCAKey)
	logger.Always("Writing: %s", f)
	err = ioutil.WriteFile(f, caKey, 0600)
	if err != nil {
		return fmt.Errorf("error writing [%s]: %v", f, err)
	}

	// --- Write server.key
	serverKey, err := g.ServerKey.MarshalPKCS1PrivateKeyPEM()
	if err != nil {
		return fmt.Errorf("unable to marshal PEM data for serverKey: %v", err)
	}
	f = filepath.Join(path, DefaultServerKey)
	logger.Always("Writing: %s", f)
	err = ioutil.WriteFile(f, serverKey, 0600)
	if err != nil {
		return fmt.Errorf("error writing [%s]: %v", f, err)
	}

	// --- Write client.key
	clientKey, err := g.ClientKey.MarshalPKCS1PrivateKeyPEM()
	if err != nil {
		return fmt.Errorf("unable to marshal PEM data for clientKey: %v", err)
	}
	f = filepath.Join(path, DefaultClientKey)
	logger.Always("Writing: %s", f)
	err = ioutil.WriteFile(f, clientKey, 0600)
	if err != nil {
		return fmt.Errorf("error writing [%s]: %v", f, err)
	}
	return nil
}

func satisfyDir(dirName string) (string, error) {
	abs, err := filepath.Abs(dirName)
	if err != nil {
		return "", fmt.Errorf("unable to calculate absolute path: %v", err)
	}
	err = os.MkdirAll(abs, 0644)
	if err == nil || os.IsExist(err) {
		return abs, nil
	}
	return "", fmt.Errorf("unable to ensure dir: %v", err)
}
