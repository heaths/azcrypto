// Copyright 2023 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

package algorithm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/heaths/azcrypto/internal"
	"github.com/stretchr/testify/require"
)

func TestNewECDsa(t *testing.T) {
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
				Kty: to.Ptr(azkeys.JSONWebKeyTypeRSA),
			},
			errMsg: `ECDsa does not support key type "RSA"`,
		},
		{
			name: "missing crv",
			key: azkeys.JSONWebKey{
				Kty: to.Ptr(azkeys.JSONWebKeyTypeEC),
			},
			errMsg: "ECDsa requires curve name",
		},
		{
			name: "with keyID",
			key: azkeys.JSONWebKey{
				Kty: to.Ptr(azkeys.JSONWebKeyTypeEC),
				Crv: to.Ptr(azkeys.JSONWebKeyCurveNameP256),
				KID: to.Ptr(azkeys.ID("kid")),
			},
			keyID: "kid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			alg, err := newECDsa(tt.key)
			if tt.errMsg != "" {
				require.EqualError(t, err, tt.errMsg)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.keyID, alg.keyID)
		})
	}
}

func TestFromCurve(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		crv  azkeys.JSONWebKeyCurveName
		want elliptic.Curve
		err  error
	}{
		{
			name: "p256",
			crv:  azkeys.JSONWebKeyCurveNameP256,
			want: elliptic.P256(),
		},
		{
			name: "p256k",
			crv:  azkeys.JSONWebKeyCurveNameP256K,
			err:  internal.ErrUnsupported,
		},
		{
			name: "p384",
			crv:  azkeys.JSONWebKeyCurveNameP384,
			want: elliptic.P384(),
		},
		{
			name: "p521",
			crv:  azkeys.JSONWebKeyCurveNameP521,
			want: elliptic.P521(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			curve, err := fromCurve(tt.crv)
			if tt.err != nil {
				require.ErrorIs(t, err, tt.err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, curve)
		})
	}
}

func TestECDsa_Verify(t *testing.T) {
	t.Parallel()

	digest := hash("message", crypto.SHA256)
	signature, err := hex.DecodeString("6f1ebd371ccae1a455bb709c5bb2c3e999ede7ed34b8e5e3d3994508f238c33c48f979c986182f6b8f7bd3fb277cc3a6c10f42ee906d18420d6ee7895720fca8")
	require.NoError(t, err)

	result, err := testECDsa.Verify(azkeys.JSONWebKeySignatureAlgorithmES256, digest, signature)
	require.NoError(t, err)
	require.True(t, result.Valid)

	_, err = testECDsa.Verify(azkeys.JSONWebKeySignatureAlgorithmES256K, digest, signature)
	require.ErrorIs(t, err, internal.ErrUnsupported)

	_, err = testECDsa.Verify(azkeys.JSONWebKeySignatureAlgorithmPS256, digest, signature)
	require.ErrorIs(t, err, internal.ErrUnsupported)
}

var testECDsa = ECDsa{
	pub: ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     base64ToBigInt("7WxNBlctcTGSin66Wagm+TjuJNkakZ66/kBWbrEXH7A="),
		Y:     base64ToBigInt("eezcbUP083FjPhwp+uTTXiJVKI7/j+IMYMl4uYrF95Y="),
	},
}
