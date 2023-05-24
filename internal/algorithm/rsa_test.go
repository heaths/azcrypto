// Copyright 2023 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

package algorithm

import (
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
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
