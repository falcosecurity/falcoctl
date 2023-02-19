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

package tls_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/falcosecurity/falcoctl/pkg/install/tls"
)

func TestNewKeyGenerator(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		given tls.DSAType
	}{
		"rsa with default settings": {
			tls.RSAType,
		},
		"ecdsa with default settings": {
			tls.ECDSAType,
		},
	}

	for name, v := range tests {
		v := v

		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got := tls.NewKeyGenerator(v.given)
			assert.NotNil(t, got)
		})
	}
}

func TestGenerateKeyRSA(t *testing.T) {
	t.Parallel()

	given, err := tls.NewKeyGenerator(tls.RSAType).GenerateKey()
	assert.Nil(t, err)

	key, ok := given.(*rsa.PrivateKey)
	assert.True(t, ok)

	buf, err := x509.MarshalPKCS8PrivateKey(key)
	assert.Nil(t, err)

	got, err := x509.ParsePKCS8PrivateKey(buf)
	assert.Nil(t, err)
	assert.EqualValues(t, given, got)
}

func TestGenerateKeyECDSA(t *testing.T) {
	t.Parallel()

	given, err := tls.NewKeyGenerator(tls.ECDSAType).GenerateKey()
	assert.Nil(t, err)

	key, ok := given.(*ecdsa.PrivateKey)
	assert.True(t, ok)

	buf, err := x509.MarshalPKCS8PrivateKey(key)
	assert.Nil(t, err)

	got, err := x509.ParsePKCS8PrivateKey(buf)
	assert.Nil(t, err)
	assert.EqualValues(t, given, got)
}

func TestPEMEncode(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		given tls.DSAKeyGenerator
	}{
		"rsa with default settings": {
			tls.NewKeyGenerator(tls.RSAType),
		},
		"ecdsa with default settings": {
			tls.NewKeyGenerator(tls.ECDSAType),
		},
	}

	for name, v := range tests {
		v := v

		t.Run(name, func(t *testing.T) {
			t.Parallel()

			key, _ := v.given.GenerateKey()
			buf, err := v.given.PEMEncode(key)
			assert.Nil(t, err)
			assert.NotNil(t, buf)
		})
	}
}

func TestRSASize(t *testing.T) {
	t.Parallel()

	gen := tls.NewKeyGenerator(tls.RSAType)
	key, _ := gen.GenerateKey()

	k, _ := key.(*rsa.PrivateKey)
	assert.Equal(t, 2048, k.N.BitLen())

	g, _ := gen.(*tls.RSAKeyGenerator)
	g.SetSize(4096)
	key, _ = g.GenerateKey()
	k, _ = key.(*rsa.PrivateKey)
	assert.Equal(t, 4096, k.N.BitLen())
}

func TestECDSASize(t *testing.T) {
	t.Parallel()

	gen := tls.NewKeyGenerator(tls.ECDSAType)
	key, _ := gen.GenerateKey()

	k, _ := key.(*ecdsa.PrivateKey)
	assert.Equal(t, elliptic.P224(), k.Curve)

	g, _ := gen.(*tls.ECDSAKeyGenerator)
	g.SetCurve(elliptic.P521())
	key, _ = g.GenerateKey()
	k, _ = key.(*ecdsa.PrivateKey)
	assert.Equal(t, elliptic.P521(), k.Curve)
}
