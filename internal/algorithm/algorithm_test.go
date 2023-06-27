// Copyright 2023 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

package algorithm

import (
	"crypto"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/heaths/azcrypto/internal"
	"github.com/stretchr/testify/require"
)

func TestNewAlgorithm(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		key  azkeys.JSONWebKey
		alg  any
		err  error
	}{
		{
			name: "missing kty",
			key:  azkeys.JSONWebKey{},
			err:  internal.ErrUnsupported,
		},
		{
			name: "unsupported kty",
			key: azkeys.JSONWebKey{
				Kty: to.Ptr(azkeys.KeyType("unknown")),
			},
			err: internal.ErrUnsupported,
		},
		{
			name: "ec",
			key: azkeys.JSONWebKey{
				Kty: to.Ptr(azkeys.KeyTypeEC),
				Crv: to.Ptr(azkeys.CurveNameP256),
				X:   []byte{0},
				Y:   []byte{1},
			},
			alg: ECDsa{},
		},
		{
			name: "ec-hsm",
			key: azkeys.JSONWebKey{
				Kty: to.Ptr(azkeys.KeyTypeECHSM),
				Crv: to.Ptr(azkeys.CurveNameP256),
				X:   []byte{0},
				Y:   []byte{1},
			},
			alg: ECDsa{},
		},
		{
			name: "rsa",
			key: azkeys.JSONWebKey{
				Kty: to.Ptr(azkeys.KeyTypeRSA),
				N:   []byte{0},
				E:   []byte{1},
			},
			alg: RSA{},
		},
		{
			name: "rsa-hsm",
			key: azkeys.JSONWebKey{
				Kty: to.Ptr(azkeys.KeyTypeRSAHSM),
				N:   []byte{0},
				E:   []byte{1},
			},
			alg: RSA{},
		},
		{
			name: "oct",
			key: azkeys.JSONWebKey{
				Kty: to.Ptr(azkeys.KeyTypeOct),
				K:   base64ToBytes("9M09IArT3CEMYXEKBNdhgw=="), // cspell:disable-line,
			},
			alg: AES{},
		},
		{
			name: "oct-hsm",
			key: azkeys.JSONWebKey{
				Kty: to.Ptr(azkeys.KeyTypeOctHSM),
				K:   base64ToBytes("9M09IArT3CEMYXEKBNdhgw=="), // cspell:disable-line,
			},
			alg: AES{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			alg, err := NewAlgorithm(tt.key)
			if tt.err != nil {
				require.ErrorIs(t, err, tt.err)
				return
			}
			require.NoError(t, err)
			require.IsType(t, tt.alg, alg)
		})
	}
}

func TestAs(t *testing.T) {
	t.Parallel()

	var encrypter Encrypter
	var aesEncrypter AESEncrypter
	var signer Signer
	tests := []struct {
		name string
		key  azkeys.JSONWebKey
		alg  any
	}{
		{
			name: "ec",
			key: azkeys.JSONWebKey{
				Kty: to.Ptr(azkeys.KeyTypeEC),
				Crv: to.Ptr(azkeys.CurveNameP256),
				X:   []byte{0},
				Y:   []byte{1},
			},
			alg: signer,
		},
		{
			name: "rsa encrypter",
			key: azkeys.JSONWebKey{
				Kty: to.Ptr(azkeys.KeyTypeRSA),
				N:   []byte{0},
				E:   []byte{1},
			},
			alg: encrypter,
		},
		{
			name: "rsa signer",
			key: azkeys.JSONWebKey{
				Kty: to.Ptr(azkeys.KeyTypeRSA),
				N:   []byte{0},
				E:   []byte{1},
			},
			alg: signer,
		},
		{
			name: "oct",
			key: azkeys.JSONWebKey{
				Kty: to.Ptr(azkeys.KeyTypeOct),
				K:   base64ToBytes("9M09IArT3CEMYXEKBNdhgw=="), // cspell:disable-line,
			},
			alg: aesEncrypter,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			alg, err := NewAlgorithm(tt.key)
			require.NoError(t, err)
			require.True(t, As(alg, &tt.alg))

			var decrypter crypto.Decrypter
			require.False(t, As(alg, &decrypter))
			require.Nil(t, decrypter)
		})
	}

	require.False(t, As(nil, &signer))
	require.Nil(t, signer)

	require.Panics(t, func() {
		As[Signer](RSA{}, nil)
	})
}

func TestGetHash(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		alg  SignAlgorithm
		h    crypto.Hash
		err  error
	}{
		{
			name: "es256",
			alg:  azkeys.SignatureAlgorithmES256,
			h:    crypto.SHA256,
		},
		{
			name: "es256k",
			alg:  azkeys.SignatureAlgorithmES256K,
			h:    crypto.SHA256,
		},
		{
			name: "es384",
			alg:  azkeys.SignatureAlgorithmES384,
			h:    crypto.SHA384,
		},
		{
			name: "es512",
			alg:  azkeys.SignatureAlgorithmES512,
			h:    crypto.SHA512,
		},
		{
			name: "ps256",
			alg:  azkeys.SignatureAlgorithmPS256,
			h:    crypto.SHA256,
		},
		{
			name: "ps384",
			alg:  azkeys.SignatureAlgorithmPS384,
			h:    crypto.SHA384,
		},
		{
			name: "ps512",
			alg:  azkeys.SignatureAlgorithmPS512,
			h:    crypto.SHA512,
		},
		{
			name: "RS256",
			alg:  azkeys.SignatureAlgorithmRS256,
			h:    crypto.SHA256,
		},
		{
			name: "RS384",
			alg:  azkeys.SignatureAlgorithmRS384,
			h:    crypto.SHA384,
		},
		{
			name: "RS256",
			alg:  azkeys.SignatureAlgorithmRS512,
			h:    crypto.SHA512,
		},
		{
			name: "unsupported",
			alg:  azkeys.SignatureAlgorithm("unsupported"),
			err:  internal.ErrUnsupported,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, err := GetHash(tt.alg)
			if tt.err != nil {
				require.ErrorIs(t, err, tt.err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.h, h)
		})
	}
}

func TestSupportsAlgorithm(t *testing.T) {
	require.True(t, supportsAlgorithm(
		azkeys.EncryptionAlgorithmA128CBC,
		azkeys.EncryptionAlgorithmA128CBC,
		azkeys.EncryptionAlgorithmA192CBC,
		azkeys.EncryptionAlgorithmA256CBC,
	))

	require.False(t, supportsAlgorithm(
		azkeys.EncryptionAlgorithmA128CBCPAD,
		azkeys.EncryptionAlgorithmA128CBC,
		azkeys.EncryptionAlgorithmA192CBC,
		azkeys.EncryptionAlgorithmA256CBC,
	))
}

// base64ToBigInt decodes a base64 string to a big.Int.
func base64ToBigInt(s string) *big.Int {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return new(big.Int).SetBytes(b)
}

// base64ToBytes decodes a base64 string to a []byte.
func base64ToBytes(s string) []byte {
	dst, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return dst
}

// hexToBytes decodes a hexadecimal string to a []byte.
func hexToBytes(s string) []byte {
	dst, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return dst
}

// hash a plaintext string using SHA256.
func hash(plaintext string, hash crypto.Hash) []byte {
	h := hash.New()
	h.Write([]byte(plaintext))
	return h.Sum(nil)
}
