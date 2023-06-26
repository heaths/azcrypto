// Copyright 2023 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

package algorithm

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
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
	keyID   string
	block   cipher.Block
	keySize int
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
		keyID:   keyID,
		block:   block,
		keySize: len(key.K),
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

	if size := requiresKeySize(algorithm, a); size > a.keySize {
		return EncryptResult{}, fmt.Errorf("%s requires key size %d bytes or larger", algorithm, size)
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

func (a AES) DecryptAESCBC(algorithm EncryptAESCBCAlgorithm, ciphertext, iv []byte) (DecryptResult, error) {
	// TODO: Consider implementing local PKCS7 padding support should we need local encryption support.
	if !supportsAlgorithm(
		algorithm,
		azkeys.JSONWebKeyEncryptionAlgorithmA128CBC,
		azkeys.JSONWebKeyEncryptionAlgorithmA192CBC,
		azkeys.JSONWebKeyEncryptionAlgorithmA256CBC,
	) {
		return DecryptResult{}, internal.ErrUnsupported
	}

	if size := requiresKeySize(algorithm, a); size > a.keySize {
		return DecryptResult{}, fmt.Errorf("%s requires key size %d bytes or larger", algorithm, size)
	}

	blockSize := a.block.BlockSize()
	if len(ciphertext)%blockSize != 0 {
		return DecryptResult{}, fmt.Errorf("size of ciphertext not a multiple of block size")
	}

	dec := cipher.NewCBCDecrypter(a.block, iv)
	plaintext := make([]byte, len(ciphertext))
	dec.CryptBlocks(plaintext, ciphertext)

	return DecryptResult{
		Algorithm: algorithm,
		KeyID:     a.keyID,
		Plaintext: plaintext,
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

	if size := requiresKeySize(algorithm, a); size > a.keySize {
		return EncryptResult{}, fmt.Errorf("%s requires key size %d bytes or larger", algorithm, size)
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

func (a AES) DecryptAESGCM(algorithm EncryptAESGCMAlgorithm, ciphertext, nonce, authenticationTag, additionalAuthenticatedData []byte) (DecryptResult, error) {
	if !supportsAlgorithm(
		algorithm,
		azkeys.JSONWebKeyEncryptionAlgorithmA128GCM,
		azkeys.JSONWebKeyEncryptionAlgorithmA192GCM,
		azkeys.JSONWebKeyEncryptionAlgorithmA256GCM,
	) {
		return DecryptResult{}, internal.ErrUnsupported
	}

	if size := requiresKeySize(algorithm, a); size > a.keySize {
		return DecryptResult{}, fmt.Errorf("%s requires key size %d bytes or larger", algorithm, size)
	}

	gcm, err := cipher.NewGCM(a.block)
	if err != nil {
		return DecryptResult{}, err
	}

	c := make([]byte, len(ciphertext)+len(authenticationTag))
	copy(c, ciphertext)
	copy(c[len(ciphertext):], authenticationTag)

	plaintext, err := gcm.Open(nil, nonce, c, additionalAuthenticatedData)
	if err != nil {
		return DecryptResult{}, err
	}

	return DecryptResult{
		Algorithm: algorithm,
		KeyID:     a.keyID,
		Plaintext: plaintext,
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

	if size := requiresKeySize(algorithm, a); size > a.keySize {
		return WrapKeyResult{}, fmt.Errorf("%s requires key size %d bytes or larger", algorithm, size)
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

func (a AES) UnwrapKey(algorithm WrapKeyAlgorithm, encryptedKey []byte) (UnwrapKeyResult, error) {
	if !supportsAlgorithm(
		algorithm,
		azkeys.JSONWebKeyEncryptionAlgorithmA128KW,
		azkeys.JSONWebKeyEncryptionAlgorithmA192KW,
		azkeys.JSONWebKeyEncryptionAlgorithmA256KW,
	) {
		return UnwrapKeyResult{}, internal.ErrUnsupported
	}

	if size := requiresKeySize(algorithm, a); size > a.keySize {
		return UnwrapKeyResult{}, fmt.Errorf("%s requires key size %d bytes or larger", algorithm, size)
	}

	plaintext, err := unwrap(a.block, encryptedKey)
	if err != nil {
		return UnwrapKeyResult{}, err
	}

	return UnwrapKeyResult{
		Algorithm: algorithm,
		KeyID:     a.keyID,
		Key:       plaintext,
	}, nil
}

func requiresKeySize[T ~string](algorithm T, a AES) int {
	switch algorithm {
	case T(azkeys.JSONWebKeyEncryptionAlgorithmA128CBC):
		fallthrough
	case T(azkeys.JSONWebKeyEncryptionAlgorithmA128CBCPAD):
		fallthrough
	case T(azkeys.JSONWebKeyEncryptionAlgorithmA128GCM):
		fallthrough
	case T(azkeys.JSONWebKeyEncryptionAlgorithmA128KW):
		return 16

	case T(azkeys.JSONWebKeyEncryptionAlgorithmA192CBC):
		fallthrough
	case T(azkeys.JSONWebKeyEncryptionAlgorithmA192CBCPAD):
		fallthrough
	case T(azkeys.JSONWebKeyEncryptionAlgorithmA192GCM):
		fallthrough
	case T(azkeys.JSONWebKeyEncryptionAlgorithmA192KW):
		return 24

	case T(azkeys.JSONWebKeyEncryptionAlgorithmA256CBC):
		fallthrough
	case T(azkeys.JSONWebKeyEncryptionAlgorithmA256CBCPAD):
		fallthrough
	case T(azkeys.JSONWebKeyEncryptionAlgorithmA256GCM):
		fallthrough
	case T(azkeys.JSONWebKeyEncryptionAlgorithmA256KW):
		return 32

	default:
		panic("unexpected algorithm")
	}
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

func unwrap(block cipher.Block, ciphertext []byte) ([]byte, error) {
	if len(ciphertext)%8 != 0 {
		return nil, fmt.Errorf("length of ciphertext not multiple of 64 bits")
	}

	// Initialize variables.
	a := make([]byte, 8)
	copy(a, ciphertext[:8])

	n := len(ciphertext)/8 - 1
	r := make([][]byte, n)
	for i := range r {
		r[i] = make([]byte, 8)
		copy(r[i], ciphertext[(i+1)*8:])
	}

	// Compute intermediate values.
	for j := 5; j >= 0; j-- {
		for i := n; i >= 1; i-- {
			// B = AES-1(K, (A ^ t) | R[i]) where t = n*j+i
			t := make([]byte, 8)
			binary.BigEndian.PutUint64(t, uint64(n*j+i))

			b := make([]byte, 16)
			xorBytes(b, a, t)
			copy(b[8:], r[i-1])
			block.Decrypt(b, b)

			// A = MSB(64, B)
			copy(a, b[:8])

			// R[i] = LSB(64, B)
			copy(r[i-1], b[8:])
		}
	}

	// Integrity check.
	if subtle.ConstantTimeCompare(a, defaultIV) != 1 {
		return nil, fmt.Errorf("integrity check failed")
	}

	// Output results.
	p := make([]byte, n*8)
	for i := range r {
		copy(p[i*8:], r[i])
	}

	return p, nil
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
	for i := 0; i < n; i++ {
		dst[i] = x[i] ^ y[i]
	}
}
