// Copyright 2023 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

package algorithm

import (
	"crypto/rsa"
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/heaths/azcrypto/internal"
)

type RSA struct {
	keyID string
	pub   rsa.PublicKey
}

func newRSA(key azkeys.JSONWebKey) (RSA, error) {
	if *key.Kty != azkeys.JSONWebKeyTypeRSA && *key.Kty != azkeys.JSONWebKeyTypeRSAHSM {
		return RSA{}, fmt.Errorf("RSA does not support key type %q", *key.Kty)
	}

	var keyID string
	if key.KID != nil {
		keyID = string(*key.KID)
	}

	eb := ensure(key.E, 4)
	eu := binary.BigEndian.Uint32(eb)

	return RSA{
		keyID: keyID,
		pub: rsa.PublicKey{
			N: new(big.Int).SetBytes(key.N),
			E: int(eu),
		},
	}, nil
}

func (r RSA) Encrypt(algorithm EncryptionAlgorithm, plaintext []byte) (EncryptResult, error) {
	return EncryptResult{}, internal.ErrUnsupported
}

func (r RSA) Verify(algorithm SignatureAlgorithm, digest, signature []byte) (VerifyResult, error) {
	hash, err := GetHash(algorithm)
	if err != nil {
		return VerifyResult{}, err
	}

	err = rsa.VerifyPSS(&r.pub, hash, digest, signature, nil)
	return VerifyResult{
		Algorithm: algorithm,
		KeyID:     r.keyID,
		Valid:     err == nil,
	}, nil
}

func (r RSA) WrapKey(algorithm KeyWrapAlgorithm, key []byte) (WrapKeyResult, error) {
	return WrapKeyResult{}, internal.ErrUnsupported
}

func ensure(src []byte, size int) []byte {
	l := len(src)
	if l < size {
		dst := make([]byte, size)
		copy(dst[size-l:], src)
		return dst
	}

	if l > size {
		return src[l-size:]
	}

	return src
}
