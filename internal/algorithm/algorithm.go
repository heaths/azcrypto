// Copyright 2023 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

package algorithm

import (
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/heaths/azcrypto/internal"
)

type SignatureAlgorithm = azkeys.JSONWebKeySignatureAlgorithm

type Algorithm interface {
	Sign(algorithm SignatureAlgorithm, digest []byte) (SignResult, error)
	Verify(algorithm SignatureAlgorithm, digest, signature []byte) (VerifyResult, error)
}

func Wrap(key azkeys.JSONWebKey) (Algorithm, error) {
	if key.Kty == nil {
		return nil, internal.ErrUnsupported
	}

	switch *key.Kty {
	case azkeys.JSONWebKeyTypeEC:
		fallthrough
	case azkeys.JSONWebKeyTypeECHSM:
		return newECDsa(key)

	default:
		return nil, internal.ErrUnsupported
	}
}

type SignResult struct {
	// Algorithm is algorithm used to sign.
	Algorithm SignatureAlgorithm

	// KeyID is the key ID used to sign. This key ID should be retained.
	KeyID string

	// Signature is a signed hash of the data.
	Signature []byte
}

type VerifyResult struct {
	// Algorithm is algorithm used to verify.
	Algorithm SignatureAlgorithm

	// KeyID is the key ID used to verify.
	KeyID string

	// Valid is true of the signature is valid.
	Valid bool
}
