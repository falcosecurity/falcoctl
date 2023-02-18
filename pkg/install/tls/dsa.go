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

type DSAType string

type DSAKey interface {
	Public() crypto.PublicKey
}

type DSAKeyGenerator interface {
	GenerateKey() (DSAKey, error)
	PEMEncode(key DSAKey) (*bytes.Buffer, error)
}

type RSAKeyGenerator struct {
	bitSize int
}

func (r *RSAKeyGenerator) SetSize(bits int) {
	r.bitSize = bits
}

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

type ECDSAKeyGenerator struct {
	curve elliptic.Curve
}

func (r *ECDSAKeyGenerator) SetCurve(curve elliptic.Curve) {
	r.curve = curve
}

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
