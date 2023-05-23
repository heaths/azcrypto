package algorithm

import (
	"crypto/sha256"
	"crypto/sha512"
	"hash"
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
	tests := []struct {
		name string
		alg  SignatureAlgorithm
		h    hash.Hash
		err  error
	}{
		{
			name: "es256",
			alg:  azkeys.JSONWebKeySignatureAlgorithmES256,
			h:    sha256.New(),
		},
		{
			name: "es256k",
			alg:  azkeys.JSONWebKeySignatureAlgorithmES256K,
			h:    sha256.New(),
		},
		{
			name: "es384",
			alg:  azkeys.JSONWebKeySignatureAlgorithmES384,
			h:    sha512.New384(),
		},
		{
			name: "es512",
			alg:  azkeys.JSONWebKeySignatureAlgorithmES512,
			h:    sha512.New(),
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
