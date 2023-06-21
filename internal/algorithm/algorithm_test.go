// Copyright 2023 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

package algorithm

import (
	"crypto"
	"crypto/sha256"
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
		alg  Algorithm
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

// decode a base64 string.
func decode(s string) *big.Int {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return new(big.Int).SetBytes(b)
}

// hash a plaintext string using SHA256.
func hash(plaintext string) []byte {
	h := sha256.New()
	h.Write([]byte(plaintext))
	return h.Sum(nil)
}
