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

package tls

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
)

// DSAType represents an algorithm for digital signing.
type DSAType string

// DSAKey represents a key pair used for digital signing.
type DSAKey interface {
	Public() crypto.PublicKey
}

// DSAKeyGenerator is a generator of key pairs used for digital signing.
type DSAKeyGenerator interface {
	GenerateKey() (DSAKey, error)
	PEMEncode(key DSAKey) (*bytes.Buffer, error)
}

// RSAKeyGenerator is a generator of RSA key pairs.
type RSAKeyGenerator struct {
	bitSize int
}

// SetSize sets the size of the RSA key to be generated.
func (r *RSAKeyGenerator) SetSize(bits int) {
	r.bitSize = bits
}

// GenerateKey returns an RSA key pair, with an error.
func (r *RSAKeyGenerator) GenerateKey() (DSAKey, error) {
	if r.bitSize == 0 {
		r.bitSize = RSADefaultSize
	}

	key, err := rsa.GenerateKey(rand.Reader, r.bitSize)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// PEMEncode encodes the private key in PEM format and returns a buffer and an error.
func (r *RSAKeyGenerator) PEMEncode(key DSAKey) (*bytes.Buffer, error) {
	b, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	buf := new(bytes.Buffer)
	if err := pem.Encode(buf, &pem.Block{Type: RSAPrivateKeyPEMHeader, Bytes: b}); err != nil {
		return nil, err
	}

	return buf, nil
}

// ECDSAKeyGenerator is a generator of ECDSA key pairs.
type ECDSAKeyGenerator struct {
	curve elliptic.Curve
}

// SetCurve sets the elliptic curve to generate the key.
func (r *ECDSAKeyGenerator) SetCurve(curve elliptic.Curve) {
	r.curve = curve
}

// GenerateKey returns an ECDSA key pair, with an error.
func (r *ECDSAKeyGenerator) GenerateKey() (DSAKey, error) {
	if r.curve == nil {
		r.curve = elliptic.P256()
	}

	key, err := ecdsa.GenerateKey(r.curve, rand.Reader)
	key.Public()
	if err != nil {
		return nil, err
	}
	return key, nil
}

// PEMEncode encodes the private key in PEM format and returns a buffer and an error.
func (r *ECDSAKeyGenerator) PEMEncode(key DSAKey) (*bytes.Buffer, error) {
	b, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	buf := new(bytes.Buffer)
	if err := pem.Encode(buf, &pem.Block{Type: ECDSAPrivateKeyPEMHeader, Bytes: b}); err != nil {
		return nil, err
	}

	return buf, nil
}

// NewKeyGenerator returns a new DSAKeyGenerator, based on the DSAType argument.
func NewKeyGenerator(dsa DSAType) DSAKeyGenerator {
	switch dsa {
	case RSAType:
		return &RSAKeyGenerator{}
	case ECDSAType:
		return &ECDSAKeyGenerator{}
	default:
		return &RSAKeyGenerator{}
	}
}
