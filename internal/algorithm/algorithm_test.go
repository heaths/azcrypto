// Copyright 2023 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

package algorithm

import (
	"crypto"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding/base64"
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
				Kty: to.Ptr(azkeys.JSONWebKeyType("unknown")),
			},
			err: internal.ErrUnsupported,
		},
		{
			name: "ec",
			key: azkeys.JSONWebKey{
				Kty: to.Ptr(azkeys.JSONWebKeyTypeEC),
				Crv: to.Ptr(azkeys.JSONWebKeyCurveNameP256),
				X:   []byte{0},
				Y:   []byte{1},
			},
			alg: ECDsa{},
		},
		{
			name: "ec-hsm",
			key: azkeys.JSONWebKey{
				Kty: to.Ptr(azkeys.JSONWebKeyTypeECHSM),
				Crv: to.Ptr(azkeys.JSONWebKeyCurveNameP256),
				X:   []byte{0},
				Y:   []byte{1},
			},
			alg: ECDsa{},
		},
		{
			name: "rsa",
			key: azkeys.JSONWebKey{
				Kty: to.Ptr(azkeys.JSONWebKeyTypeRSA),
				N:   []byte{0},
				E:   []byte{1},
			},
			alg: RSA{},
		},
		{
			name: "rsa-hsm",
			key: azkeys.JSONWebKey{
				Kty: to.Ptr(azkeys.JSONWebKeyTypeRSAHSM),
				N:   []byte{0},
				E:   []byte{1},
			},
			alg: RSA{},
		},
		{
			name: "oct",
			key: azkeys.JSONWebKey{
				Kty: to.Ptr(azkeys.JSONWebKeyTypeOct),
				K:   decodeBytes("9M09IArT3CEMYXEKBNdhgw=="), // cspell:disable-line,
			},
			alg: AES{},
		},
		{
			name: "oct-hsm",
			key: azkeys.JSONWebKey{
				Kty: to.Ptr(azkeys.JSONWebKeyTypeOctHSM),
				K:   decodeBytes("9M09IArT3CEMYXEKBNdhgw=="), // cspell:disable-line,
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
				Kty: to.Ptr(azkeys.JSONWebKeyTypeEC),
				Crv: to.Ptr(azkeys.JSONWebKeyCurveNameP256),
				X:   []byte{0},
				Y:   []byte{1},
			},
			alg: signer,
		},
		{
			name: "rsa encrypter",
			key: azkeys.JSONWebKey{
				Kty: to.Ptr(azkeys.JSONWebKeyTypeRSA),
				N:   []byte{0},
				E:   []byte{1},
			},
			alg: encrypter,
		},
		{
			name: "rsa signer",
			key: azkeys.JSONWebKey{
				Kty: to.Ptr(azkeys.JSONWebKeyTypeRSA),
				N:   []byte{0},
				E:   []byte{1},
			},
			alg: signer,
		},
		{
			name: "oct",
			key: azkeys.JSONWebKey{
				Kty: to.Ptr(azkeys.JSONWebKeyTypeOct),
				K:   decodeBytes("9M09IArT3CEMYXEKBNdhgw=="), // cspell:disable-line,
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
			alg:  azkeys.JSONWebKeySignatureAlgorithmES256,
			h:    crypto.SHA256,
		},
		{
			name: "es256k",
			alg:  azkeys.JSONWebKeySignatureAlgorithmES256K,
			h:    crypto.SHA256,
		},
		{
			name: "es384",
			alg:  azkeys.JSONWebKeySignatureAlgorithmES384,
			h:    crypto.SHA384,
		},
		{
			name: "es512",
			alg:  azkeys.JSONWebKeySignatureAlgorithmES512,
			h:    crypto.SHA512,
		},
		{
			name: "ps256",
			alg:  azkeys.JSONWebKeySignatureAlgorithmPS256,
			h:    crypto.SHA256,
		},
		{
			name: "ps384",
			alg:  azkeys.JSONWebKeySignatureAlgorithmPS384,
			h:    crypto.SHA384,
		},
		{
			name: "ps512",
			alg:  azkeys.JSONWebKeySignatureAlgorithmPS512,
			h:    crypto.SHA512,
		},
		{
			name: "RS256",
			alg:  azkeys.JSONWebKeySignatureAlgorithmRS256,
			h:    crypto.SHA256,
		},
		{
			name: "RS384",
			alg:  azkeys.JSONWebKeySignatureAlgorithmRS384,
			h:    crypto.SHA384,
		},
		{
			name: "RS256",
			alg:  azkeys.JSONWebKeySignatureAlgorithmRS512,
			h:    crypto.SHA512,
		},
		{
			name: "unsupported",
			alg:  azkeys.JSONWebKeySignatureAlgorithm("unsupported"),
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
		azkeys.JSONWebKeyEncryptionAlgorithmA128CBC,
		azkeys.JSONWebKeyEncryptionAlgorithmA128CBC,
		azkeys.JSONWebKeyEncryptionAlgorithmA192CBC,
		azkeys.JSONWebKeyEncryptionAlgorithmA256CBC,
	))

	require.False(t, supportsAlgorithm(
		azkeys.JSONWebKeyEncryptionAlgorithmA128CBCPAD,
		azkeys.JSONWebKeyEncryptionAlgorithmA128CBC,
		azkeys.JSONWebKeyEncryptionAlgorithmA192CBC,
		azkeys.JSONWebKeyEncryptionAlgorithmA256CBC,
	))
}

// decode a base64 string.
func decode(s string) *big.Int {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return new(big.Int).SetBytes(b)
}

// hash a plaintext string using SHA256.
func hash(plaintext string, hash crypto.Hash) []byte {
	h := hash.New()
	h.Write([]byte(plaintext))
	return h.Sum(nil)
}
