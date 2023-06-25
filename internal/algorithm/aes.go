// Copyright 2023 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

package algorithm

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/heaths/azcrypto/internal"
)

const (
	gcmNonceSize int = 12
)

var (
	// Default IV from https://www.rfc-editor.org/rfc/rfc3394
	defaultIV = []byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}
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

func (a AES) WrapKey(algorithm WrapKeyAlgorithm, key []byte) (WrapKeyResult, error) {
	if !supportsAlgorithm(
		algorithm,
		azkeys.JSONWebKeyEncryptionAlgorithmA128KW,
		azkeys.JSONWebKeyEncryptionAlgorithmA192KW,
		azkeys.JSONWebKeyEncryptionAlgorithmA256KW,
	) {
		return WrapKeyResult{}, internal.ErrUnsupported
	}

	ciphertext, err := wrap(a.block, key)
	if err != nil {
		return WrapKeyResult{}, err
	}

	return WrapKeyResult{
		Algorithm:    algorithm,
		KeyID:        a.keyID,
		EncryptedKey: ciphertext,
	}, nil
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

func wrap(block cipher.Block, plaintext []byte) ([]byte, error) {
	if len(plaintext)%8 != 0 {
		return nil, fmt.Errorf("length of plaintext not multiple of 64 bits")
	}

	// Initialize variables.
	a := make([]byte, 8)
	copy(a, defaultIV)

	n := len(plaintext) / 8
	r := make([][]byte, n)
	for i := range r {
		r[i] = make([]byte, 8)
		copy(r[i], plaintext[i*8:])
	}

	// Calculate intermediate values.
	for j := 0; j <= 5; j++ {
		for i := 1; i <= n; i++ {
			// B = AES(K, A | R[i])
			b := make([]byte, 16)
			copy(b, a)
			copy(b[8:], r[i-1])
			block.Encrypt(b, b)

			// A = MSB(64, B) ^ t where t = (n*j)+i
			t := make([]byte, 8)
			binary.BigEndian.PutUint64(t, uint64(n*j+i))
			xorBytes(a, b[:8], t)

			// R[i] = LSB(64, B)
			copy(r[i-1], b[8:])
		}
	}

	// Output the results.
	c := make([]byte, (n+1)*8)
	copy(c, a)
	for i := 1; i <= n; i++ {
		copy(c[i*8:], r[i-1])
	}

	return c, nil
}

func xorBytes(dst, x, y []byte) {
	n := len(x)
	if len(y) < n {
		n = len(y)
	}
	if n == 0 {
		return
	}
	if n > len(dst) {
		panic("dst too short")
	}
	for i := range dst {
		dst[i] = x[i] ^ y[i]
	}
}
