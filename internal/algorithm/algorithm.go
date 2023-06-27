// Copyright 2023 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

package algorithm

import (
	"crypto"
	_ "crypto/sha256"
	_ "crypto/sha512"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/heaths/azcrypto/internal"
	_ "github.com/heaths/azcrypto/internal/test"
)

type EncryptAlgorithm = azkeys.EncryptionAlgorithm
type EncryptAESCBCAlgorithm = azkeys.EncryptionAlgorithm
type EncryptAESGCMAlgorithm = azkeys.EncryptionAlgorithm
type SignAlgorithm = azkeys.SignatureAlgorithm
type WrapKeyAlgorithm = azkeys.EncryptionAlgorithm

type AESEncrypter interface {
	EncryptAESCBC(algorithm EncryptAESCBCAlgorithm, plaintext, iv []byte) (EncryptResult, error)
	DecryptAESCBC(algorithm EncryptAESCBCAlgorithm, ciphertext, iv []byte) (DecryptResult, error)
	EncryptAESGCM(algorithm EncryptAESGCMAlgorithm, plaintext, nonce, additionalAuthenticatedData []byte) (EncryptResult, error)
	DecryptAESGCM(algorithm EncryptAESGCMAlgorithm, ciphertext, nonce, authenticationTag, additionalAuthenticatedData []byte) (DecryptResult, error)
}

type Encrypter interface {
	Encrypt(algorithm EncryptAlgorithm, plaintext []byte) (EncryptResult, error)
}

type Signer interface {
	Verify(algorithm SignAlgorithm, digest, signature []byte) (VerifyResult, error)
}

type KeyWrapper interface {
	WrapKey(algorithm WrapKeyAlgorithm, key []byte) (WrapKeyResult, error)
	UnwrapKey(algorithm WrapKeyAlgorithm, encryptedKey []byte) (UnwrapKeyResult, error)
}

func As[T any](algorithm any, target *T) bool {
	if algorithm == nil {
		return false
	}
	if target == nil {
		panic("target cannot be nil")
	}
	if v, ok := algorithm.(T); ok {
		*target = v
		return true
	}
	return false
}

func NewAlgorithm(key azkeys.JSONWebKey) (any, error) {
	if key.Kty == nil {
		return nil, internal.ErrUnsupported
	}

	switch *key.Kty {
	// ECDsa
	case azkeys.KeyTypeEC, azkeys.KeyTypeECHSM:
		return newECDsa(key)

	// RSA
	case azkeys.KeyTypeRSA, azkeys.KeyTypeRSAHSM:
		return newRSA(key)

	// oct
	case azkeys.KeyTypeOct, azkeys.KeyTypeOctHSM:
		return newAES(key)

	default:
		return nil, internal.ErrUnsupported
	}
}

func GetHash(algorithm SignAlgorithm) (crypto.Hash, error) {
	switch algorithm {
	case azkeys.SignatureAlgorithmPS256,
		azkeys.SignatureAlgorithmRS256,
		azkeys.SignatureAlgorithmES256,
		azkeys.SignatureAlgorithmES256K:
		return crypto.SHA256, nil

	case azkeys.SignatureAlgorithmPS384,
		azkeys.SignatureAlgorithmRS384,
		azkeys.SignatureAlgorithmES384:
		return crypto.SHA384, nil

	case azkeys.SignatureAlgorithmPS512,
		azkeys.SignatureAlgorithmRS512,
		azkeys.SignatureAlgorithmES512:
		return crypto.SHA512, nil

	default:
		return 0, internal.ErrUnsupported
	}
}

type EncryptResult struct {
	// Algorithm is encryption algorithm used to encrypt.
	Algorithm EncryptAlgorithm

	// KeyID is the key ID used to encrypt. This key ID should be retained.
	KeyID string

	// Ciphertext is the encryption result.
	Ciphertext []byte

	// IV is the initialization vector used to encrypt using AES-CBC.
	IV []byte

	// Nonce is the nonce used to encrypt using AES-GCM.
	Nonce []byte

	// AdditionalAuthenticatedData passed to EncryptAESGCM.
	AdditionalAuthenticatedData []byte

	// AuthenticationTag returned from EncryptAESGCM.
	AuthenticationTag []byte
}

type DecryptResult struct {
	// Algorithm is encryption algorithm used to decrypt.
	Algorithm EncryptAlgorithm

	// KeyID is the key ID used to decrypt.
	KeyID string

	// Plaintext is the decryption result.
	Plaintext []byte
}

type SignResult struct {
	// Algorithm is the signature algorithm used to sign.
	Algorithm SignAlgorithm

	// KeyID is the key ID used to sign. This key ID should be retained.
	KeyID string

	// Signature is a signed hash of the data.
	Signature []byte
}

type VerifyResult struct {
	// Algorithm is the signature algorithm used to verify.
	Algorithm SignAlgorithm

	// KeyID is the key ID used to verify.
	KeyID string

	// Valid is true of the signature is valid.
	Valid bool
}

type WrapKeyResult struct {
	// Algorithm is the key wrap algorithm used to wrap.
	Algorithm WrapKeyAlgorithm

	// KeyID is the key ID used to wrap. This key ID should be retained.
	KeyID string

	// EncryptedKey is the wrapped (encrypted) key.
	EncryptedKey []byte
}

type UnwrapKeyResult struct {
	// Algorithm is the key wrap algorithm used to unwrap.
	Algorithm WrapKeyAlgorithm

	// KeyID is the key ID used to unwrap.
	KeyID string

	// Key is the unwrapped (decrypted) key.
	Key []byte
}

func supportsAlgorithm[T ~string](algorithm T, supports ...T) bool {
	for _, supported := range supports {
		if algorithm == supported {
			return true
		}
	}
	return false
}
