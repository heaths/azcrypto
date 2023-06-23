// Copyright 2023 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

package algorithm

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/heaths/azcrypto/internal"
)

const (
	gcmNonceSize int = 12
)

type AES struct {
	keyID string
	block cipher.Block
}

func newAES(key azkeys.JSONWebKey) (AES, error) {
	if *key.Kty != azkeys.JSONWebKeyTypeOct && *key.Kty != azkeys.JSONWebKeyTypeOctHSM {
		return AES{}, fmt.Errorf("AES does not support key type %q", *key.Kty)
	}

	if len(key.K) == 0 {
		return AES{}, fmt.Errorf("key unavailable")
	}

	block, err := aes.NewCipher(key.K)
	if err != nil {
		return AES{}, err
	}

	var keyID string
	if key.KID != nil {
		keyID = string(*key.KID)
	}

	return AES{
		keyID: keyID,
		block: block,
	}, nil
}

func (a AES) Encrypt(algorithm EncryptAlgorithm, plaintext []byte) (EncryptResult, error) {
	return EncryptResult{}, internal.ErrUnsupported
}

func (a AES) EncryptAESCBC(algorithm EncryptAESCBCAlgorithm, plaintext, iv []byte) (EncryptResult, error) {
	// TODO: Consider implementing local PKCS7 padding support should we need local encryption support.
	if !supportsAlgorithm(
		algorithm,
		azkeys.JSONWebKeyEncryptionAlgorithmA128CBC,
		azkeys.JSONWebKeyEncryptionAlgorithmA192CBC,
		azkeys.JSONWebKeyEncryptionAlgorithmA256CBC,
	) {
		return EncryptResult{}, internal.ErrUnsupported
	}

	blockSize := a.block.BlockSize()
	if len(plaintext)%blockSize != 0 {
		return EncryptResult{}, fmt.Errorf("size of plaintext not a multiple of block size")
	}

	enc := cipher.NewCBCEncrypter(a.block, iv)
	ciphertext := make([]byte, len(plaintext))
	enc.CryptBlocks(ciphertext, plaintext)

	return EncryptResult{
		Algorithm:  algorithm,
		KeyID:      a.keyID,
		Ciphertext: ciphertext,
		IV:         iv,
	}, nil
}

func (a AES) EncryptAESGCM(algorithm EncryptAESGCMAlgorithm, plaintext, nonce, additionalAuthenticatedData []byte) (EncryptResult, error) {
	if !supportsAlgorithm(
		algorithm,
		azkeys.JSONWebKeyEncryptionAlgorithmA128GCM,
		azkeys.JSONWebKeyEncryptionAlgorithmA192GCM,
		azkeys.JSONWebKeyEncryptionAlgorithmA256GCM,
	) {
		return EncryptResult{}, internal.ErrUnsupported
	}

	gcm, err := cipher.NewGCM(a.block)
	if err != nil {
		return EncryptResult{}, err
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, additionalAuthenticatedData)
	return EncryptResult{
		Algorithm:                   algorithm,
		KeyID:                       a.keyID,
		Ciphertext:                  ciphertext[:len(plaintext)],
		Nonce:                       nonce,
		AdditionalAuthenticatedData: additionalAuthenticatedData,
		AuthenticationTag:           ciphertext[len(plaintext):],
	}, nil
}

func (a AES) Verify(algorithm SignAlgorithm, digest, signature []byte) (VerifyResult, error) {
	return VerifyResult{}, internal.ErrUnsupported
}

func (a AES) WrapKey(algorithm WrapKeyAlgorithm, key []byte) (WrapKeyResult, error) {
	return WrapKeyResult{}, internal.ErrUnsupported
}

func AESGenerateIV(rand io.Reader) ([]byte, error) {
	iv := make([]byte, aes.BlockSize)
	_, err := rand.Read(iv)
	return iv, err
}

func AESGenerateNonce(rand io.Reader) ([]byte, error) {
	nonce := make([]byte, gcmNonceSize)
	_, err := rand.Read(nonce)
	return nonce, err
}
