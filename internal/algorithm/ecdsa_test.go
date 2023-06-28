// Copyright 2023 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

package algorithm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/heaths/azcrypto/internal"
	"github.com/heaths/azcrypto/internal/test"
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
				Kty: to.Ptr(azkeys.KeyTypeRSA),
			},
			errMsg: `ECDsa does not support key type "RSA"`,
		},
		{
			name: "missing crv",
			key: azkeys.JSONWebKey{
				Kty: to.Ptr(azkeys.KeyTypeEC),
			},
			errMsg: "ECDsa requires curve name",
		},
		{
			name: "unsupported crv",
			key: azkeys.JSONWebKey{
				Kty: to.Ptr(azkeys.KeyTypeEC),
				Crv: to.Ptr(azkeys.CurveName("invalid")),
			},
			errMsg: "unsupported crv: invalid",
		},
		{
			name: "missing x",
			key: azkeys.JSONWebKey{
				Kty: to.Ptr(azkeys.KeyTypeEC),
				Crv: to.Ptr(azkeys.CurveNameP256),
			},
			errMsg: "ECDsa requires public key coordinates X, Y",
		},
		{
			name: "missing x",
			key: azkeys.JSONWebKey{
				Kty: to.Ptr(azkeys.KeyTypeEC),
				Crv: to.Ptr(azkeys.CurveNameP256),
				X:   []byte{0},
			},
			errMsg: "ECDsa requires public key coordinates X, Y",
		},
		{
			name: "with keyID",
			key: azkeys.JSONWebKey{
				Kty: to.Ptr(azkeys.KeyTypeEC),
				Crv: to.Ptr(azkeys.CurveNameP256),
				KID: to.Ptr(azkeys.ID("kid")),
				X:   []byte{0},
				Y:   []byte{1},
			},
			keyID: "kid",
		},
		{
			name: "with private key",
			key: azkeys.JSONWebKey{
				Kty: to.Ptr(azkeys.KeyTypeEC),
				Crv: to.Ptr(azkeys.CurveNameP256),
				X:   []byte{0},
				Y:   []byte{1},
				D:   []byte{2},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			alg, err := newECDsa(tt.key, nil)
			if tt.errMsg != "" {
				require.EqualError(t, err, tt.errMsg)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.keyID, alg.keyID)
			require.Nil(t, alg.rand)

			if len(tt.key.D) > 0 {
				require.NotNil(t, alg.key.D)
			}
		})
	}
}

func TestFromCurve(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		crv  azkeys.CurveName
		want elliptic.Curve
		err  error
	}{
		{
			name: "p256",
			crv:  azkeys.CurveNameP256,
			want: elliptic.P256(),
		},
		{
			name: "p256k",
			crv:  azkeys.CurveNameP256K,
			err:  internal.ErrUnsupported,
		},
		{
			name: "p384",
			crv:  azkeys.CurveNameP384,
			want: elliptic.P384(),
		},
		{
			name: "p521",
			crv:  azkeys.CurveNameP521,
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

func TestECDsa_Sign(t *testing.T) {
	t.Parallel()

	digest := test.Hash("message", crypto.SHA256)

	result, err := testECDsa.Sign(azkeys.SignatureAlgorithmES256, digest)
	require.NoError(t, err)
	require.NotNil(t, result.Signature)

	pub := ECDsa{
		key: ecdsa.PrivateKey{
			PublicKey: testECDsa.key.PublicKey,
		},
	}
	_, err = pub.Sign(azkeys.SignatureAlgorithmES256, digest)
	require.ErrorIs(t, err, internal.ErrUnsupported)

	_, err = testECDsa.Sign(azkeys.SignatureAlgorithmPS256, digest)
	require.ErrorIs(t, err, internal.ErrUnsupported)
}

func TestECDsa_Verify(t *testing.T) {
	t.Parallel()

	digest := test.Hash("message", crypto.SHA256)
	signature := test.Base64ToBytes("EZ0qpcb7h5zsXsUAijfCqWo2Y9sCHWc6Qr+23GlhEvUFrYOn/iyY7CTqbm4hApPlQ0a/rFUX6BI2eYqd9+iJsw==")

	result, err := testECDsa.Verify(azkeys.SignatureAlgorithmES256, digest, signature)
	require.NoError(t, err)
	require.True(t, result.Valid)

	_, err = testECDsa.Verify(azkeys.SignatureAlgorithmES256K, digest, signature)
	require.ErrorIs(t, err, internal.ErrUnsupported)

	_, err = testECDsa.Verify(azkeys.SignatureAlgorithmPS256, digest, signature)
	require.ErrorIs(t, err, internal.ErrUnsupported)
}

var testECDsa = ECDsa{
	key: ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     test.Base64ToBigInt("5qdQRu+fvx0HHIviw8nGheW8mkJTENsmIHIc6eLwu/g="),
			Y:     test.Base64ToBigInt("6+uNICVVURJXT9cSId4nKOSe12qgI7yRogvy11ofnsw="),
		},
		D: test.Base64ToBigInt("sgNdWgsMTntK5VH3EK5cHFO1JFjwDavLFtak38zeceo="),
	},
	rand: new(test.Rand),
}
