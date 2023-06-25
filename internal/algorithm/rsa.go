// Copyright 2023 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

package algorithm

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha256"
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

func (r RSA) Encrypt(algorithm EncryptAlgorithm, plaintext []byte) (EncryptResult, error) {
	var ciphertext []byte
	var err error

	getHash := func() crypto.Hash {
		switch algorithm {
		case azkeys.JSONWebKeyEncryptionAlgorithmRSAOAEP:
			return crypto.SHA1

		case azkeys.JSONWebKeyEncryptionAlgorithmRSAOAEP256:
			return crypto.SHA256

		default:
			panic("unexpected EncryptAlgorithm")
		}
	}

	switch algorithm {
	case azkeys.JSONWebKeyEncryptionAlgorithmRSAOAEP:
		fallthrough
	case azkeys.JSONWebKeyEncryptionAlgorithmRSAOAEP256:
		hash := getHash()
		ciphertext, err = rsa.EncryptOAEP(hash.New(), rand.Reader, &r.pub, plaintext, nil)

	case azkeys.JSONWebKeyEncryptionAlgorithmRSA15:
		ciphertext, err = rsa.EncryptPKCS1v15(rand.Reader, &r.pub, plaintext)

	default:
		return EncryptResult{}, internal.ErrUnsupported
	}

	if err != nil {
		return EncryptResult{}, err
	}

	return EncryptResult{
		Algorithm:  algorithm,
		KeyID:      r.keyID,
		Ciphertext: ciphertext,
	}, nil
}

func (r RSA) Verify(algorithm SignAlgorithm, digest, signature []byte) (VerifyResult, error) {
	var err error
	switch algorithm {
	case azkeys.JSONWebKeySignatureAlgorithmPS256:
		fallthrough
	case azkeys.JSONWebKeySignatureAlgorithmPS384:
		fallthrough
	case azkeys.JSONWebKeySignatureAlgorithmPS512:
		var hash crypto.Hash
		hash, err = GetHash(algorithm)
		if err != nil {
			return VerifyResult{}, err
		}
		err = rsa.VerifyPSS(&r.pub, hash, digest, signature, nil)

	case azkeys.JSONWebKeySignatureAlgorithmRS256:
		fallthrough
	case azkeys.JSONWebKeySignatureAlgorithmRS384:
		fallthrough
	case azkeys.JSONWebKeySignatureAlgorithmRS512:
		var hash crypto.Hash
		hash, err = GetHash(algorithm)
		if err != nil {
			return VerifyResult{}, err
		}
		err = rsa.VerifyPKCS1v15(&r.pub, hash, digest, signature)

	default:
		return VerifyResult{}, internal.ErrUnsupported
	}

	return VerifyResult{
		Algorithm: algorithm,
		KeyID:     r.keyID,
		Valid:     err == nil,
	}, nil
}

func (r RSA) WrapKey(algorithm WrapKeyAlgorithm, key []byte) (WrapKeyResult, error) {
	var encryptedKey []byte
	var err error

	getHash := func() crypto.Hash {
		switch algorithm {
		case azkeys.JSONWebKeyEncryptionAlgorithmRSAOAEP:
			return crypto.SHA1

		case azkeys.JSONWebKeyEncryptionAlgorithmRSAOAEP256:
			return crypto.SHA256

		default:
			panic("unexpected WrapKeyAlgorithm")
		}
	}

	switch algorithm {
	case azkeys.JSONWebKeyEncryptionAlgorithmRSAOAEP:
		fallthrough
	case azkeys.JSONWebKeyEncryptionAlgorithmRSAOAEP256:
		hash := getHash()
		encryptedKey, err = rsa.EncryptOAEP(hash.New(), rand.Reader, &r.pub, key, nil)

	case azkeys.JSONWebKeyEncryptionAlgorithmRSA15:
		encryptedKey, err = rsa.EncryptPKCS1v15(rand.Reader, &r.pub, key)

	default:
		return WrapKeyResult{}, internal.ErrUnsupported
	}

	if err != nil {
		return WrapKeyResult{}, err
	}

	return WrapKeyResult{
		Algorithm:    algorithm,
		KeyID:        r.keyID,
		EncryptedKey: encryptedKey,
	}, nil
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
