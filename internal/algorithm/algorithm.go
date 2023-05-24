// Copyright 2023 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

package algorithm

import (
	"crypto"
	_ "crypto/sha256"
	_ "crypto/sha512"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/heaths/azcrypto/internal"
)

type EncryptionAlgorithm = azkeys.JSONWebKeyEncryptionAlgorithm
type SignatureAlgorithm = azkeys.JSONWebKeySignatureAlgorithm
type KeyWrapAlgorithm = azkeys.JSONWebKeyEncryptionAlgorithm

type Algorithm interface {
	Encrypt(algorithm EncryptionAlgorithm, plaintext []byte) (EncryptResult, error)
	Verify(algorithm SignatureAlgorithm, digest, signature []byte) (VerifyResult, error)
	WrapKey(algorithm KeyWrapAlgorithm, key []byte) (WrapKeyResult, error)
}

func NewAlgorithm(key azkeys.JSONWebKey) (Algorithm, error) {
	if key.Kty == nil {
		return nil, internal.ErrUnsupported
	}

	switch *key.Kty {
	// ECDsa
	case azkeys.JSONWebKeyTypeEC:
		fallthrough
	case azkeys.JSONWebKeyTypeECHSM:
		return newECDsa(key)

		// RSA
	case azkeys.JSONWebKeyTypeRSA:
		fallthrough
	case azkeys.JSONWebKeyTypeRSAHSM:
		return newRSA(key)

	default:
		return nil, internal.ErrUnsupported
	}
}

func GetHash(algorithm SignatureAlgorithm) (crypto.Hash, error) {
	switch algorithm {
	case azkeys.JSONWebKeySignatureAlgorithmPS256:
		fallthrough
	case azkeys.JSONWebKeySignatureAlgorithmRS256:
		fallthrough
	case azkeys.JSONWebKeySignatureAlgorithmES256:
		fallthrough
	case azkeys.JSONWebKeySignatureAlgorithmES256K:
		return crypto.SHA256, nil

	case azkeys.JSONWebKeySignatureAlgorithmPS384:
		fallthrough
	case azkeys.JSONWebKeySignatureAlgorithmRS384:
		fallthrough
	case azkeys.JSONWebKeySignatureAlgorithmES384:
		return crypto.SHA384, nil

	case azkeys.JSONWebKeySignatureAlgorithmPS512:
		fallthrough
	case azkeys.JSONWebKeySignatureAlgorithmRS512:
		fallthrough
	case azkeys.JSONWebKeySignatureAlgorithmES512:
		return crypto.SHA512, nil

	default:
		return 0, internal.ErrUnsupported
	}
}

type EncryptResult struct {
	// Algorithm is encryption algorithm used to encrypt.
	Algorithm EncryptionAlgorithm

	// KeyID is the key ID used to encrypt. This key ID should be retained.
	KeyID string

	// Ciphertext is the encryption result.
	Ciphertext []byte
}

type DecryptResult struct {
	// Algorithm is encryption algorithm used to decrypt.
	Algorithm EncryptionAlgorithm

	// KeyID is the key ID used to decrypt.
	KeyID string

	// Plaintext is the decryption result.
	Plaintext []byte
}

type SignResult struct {
	// Algorithm is the signature algorithm used to sign.
	Algorithm SignatureAlgorithm

	// KeyID is the key ID used to sign. This key ID should be retained.
	KeyID string

	// Signature is a signed hash of the data.
	Signature []byte
}

type VerifyResult struct {
	// Algorithm is the signature algorithm used to verify.
	Algorithm SignatureAlgorithm

	// KeyID is the key ID used to verify.
	KeyID string

	// Valid is true of the signature is valid.
	Valid bool
}

type WrapKeyResult struct {
	// Algorithm is the key wrap algorithm used to wrap.
	Algorithm KeyWrapAlgorithm

	// KeyID is the key ID used to wrap. This key ID should be retained.
	KeyID string

	// EncryptedKey is the wrapped (encrypted) key.
	EncryptedKey []byte
}

type UnwrapKeyResult struct {
	// Algorithm is the key wrap algorithm used to unwrap.
	Algorithm KeyWrapAlgorithm

	// KeyID is the key ID used to unwrap.
	KeyID string

	// Key is the unwrapped (decrypted) key.
	Key []byte
}
