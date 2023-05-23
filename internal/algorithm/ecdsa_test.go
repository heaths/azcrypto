package algorithm

import (
	"crypto/elliptic"
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
