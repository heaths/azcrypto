// Copyright 2023 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

// cspell:disable

package algorithm

import (
	"crypto/rsa"
	"encoding/hex"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/heaths/azcrypto/internal"
	"github.com/stretchr/testify/require"
)

func TestNewRSA(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		key    azkeys.JSONWebKey
		keyID  string
		errMsg string
	}{
		{
			name: "unsupported kty",
			key: azkeys.JSONWebKey{
				Kty: to.Ptr(azkeys.JSONWebKeyTypeEC),
			},
			errMsg: `RSA does not support key type "EC"`,
		},
		{
			name: "with keyID",
			key: azkeys.JSONWebKey{
				Kty: to.Ptr(azkeys.JSONWebKeyTypeRSA),
				KID: to.Ptr(azkeys.ID("kid")),
			},
			keyID: "kid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			alg, err := newRSA(tt.key)
			if tt.errMsg != "" {
				require.EqualError(t, err, tt.errMsg)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.keyID, alg.keyID)
		})
	}
}

func TestEnsure(t *testing.T) {
	t.Parallel()

	sut := func(src []byte) []byte {
		return ensure(src, 4)
	}

	require.Equal(t, []byte{0x00, 0x00, 0x00, 0x00}, sut([]byte{}))
	require.Equal(t, []byte{0x00, 0x00, 0x00, 0x01}, sut([]byte{0x01}))
	require.Equal(t, []byte{0x00, 0x00, 0x02, 0x01}, sut([]byte{0x02, 0x01}))
	require.Equal(t, []byte{0x00, 0x03, 0x02, 0x01}, sut([]byte{0x03, 0x02, 0x01}))
	require.Equal(t, []byte{0x04, 0x03, 0x02, 0x01}, sut([]byte{0x04, 0x03, 0x02, 0x01}))
	require.Equal(t, []byte{0x04, 0x03, 0x02, 0x01}, sut([]byte{0x05, 0x04, 0x03, 0x02, 0x01}))
}

func TestRSA_Encrypt(t *testing.T) {
	t.Parallel()

	result, err := testRSA.Encrypt(azkeys.JSONWebKeyEncryptionAlgorithmRSAOAEP, []byte("plaintext"))
	require.NoError(t, err)
	require.Greater(t, len(result.Ciphertext), 0)
}

func TestRSA_EncryptAESCBC(t *testing.T) {
	t.Parallel()

	_, err := testRSA.EncryptAESCBC(azkeys.JSONWebKeyEncryptionAlgorithmRSAOAEP, []byte("plaintext"), nil)
	require.ErrorIs(t, err, internal.ErrUnsupported)
}

func TestRSA_EncryptAESGCM(t *testing.T) {
	t.Parallel()

	_, err := testRSA.EncryptAESGCM(azkeys.JSONWebKeyEncryptionAlgorithmRSAOAEP, []byte("plaintext"), nil, nil)
	require.ErrorIs(t, err, internal.ErrUnsupported)
}

func TestRSA_Verify(t *testing.T) {
	t.Parallel()

	digest := hash("message")
	signature, err := hex.DecodeString("270b2f33b4fce8baa316674c640c5cf8a966eea37c5cf4cbeae9293a278c174a3f86167613ee9f793f182e241b97614ece56a364542fc200f118a968bb3653820453238c35aa675426fa3a046a228b12fc78650b7c23d9096b3fd7b1a124486bf06480361aeb82d9f4252b54aee950a7a596bd13024aacc0526d6019705834dad5f081eeecbf4ce7acf8586bafea0873fb57fee5330ff59566331052770b81f83820634dfb70770b07c45949fa97033f19c626e55041d2782edb2dc4b62a609b59f9f6735af8e4eb0f94a9a8b977f932faf53beed915ecc96d327a070aa02a42b4a2038272e0ec114b70cc34038f8fc53bfdec94176f02a8329dfee99f7b725a")
	require.NoError(t, err)

	result, err := testRSA.Verify(azkeys.JSONWebKeySignatureAlgorithmPS256, digest, signature)
	require.NoError(t, err)
	require.True(t, result.Valid)
}

func TestRSA_WrapKey(t *testing.T) {
	t.Parallel()

	key := []byte{0x6d, 0x6f, 0x63, 0x6b, 0x20, 0x61, 0x65, 0x73, 0x2d, 0x31, 0x32, 0x38, 0x20, 0x6b, 0x65, 0x79}

	result, err := testRSA.WrapKey(azkeys.JSONWebKeyEncryptionAlgorithmRSAOAEP, key)
	require.NoError(t, err)
	require.Greater(t, len(result.EncryptedKey), 0)
}

var testRSA = RSA{
	pub: rsa.PublicKey{
		N: decode("7w8lfvEJnlky5LwmiBiZ7TEmOOCqUfrdlwxyiTQ/usAaldoEDf1vltIZGOGkUZa1pzElBBqXuVlzZJ2BridEKhASYwguCtM8ByQdpyQ4BnFQgPMAqqTTi2xb441y/h6sLUuCtXevNuYUI4yoVS4MeZFKAF0JVHhaeeHh47kckJimyGjaRMsQg0ONL1r047uPFZuzGSHJ5Eh0sQebTyvjciE31GjCqa5FKgEhl7c+mFEo2zt0n9qZAq8o2F8x7nf7ksOq1k684P+XHQptJIp/0MW/P23vh/5+Z/AfiCjBAR1e0Nq4YEY42f/NYzXsjQfSsOdSuFVpW5z2BsM4WIxdWQ=="),
		E: 65537, // AQAB
	},
}
