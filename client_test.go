package azcrypto

import (
	"testing"

	"github.com/heaths/azcrypto/internal/mock"
	"github.com/stretchr/testify/require"
)

func TestNewClient(t *testing.T) {
	credential := &mock.Credential{}

	client, err := NewClient("", credential, nil)
	require.Nil(t, client)
	require.EqualError(t, err, "keyID must specify a valid vault URL and key name")

	client, err = NewClient("https://myvault.vault.azure.net", credential, nil)
	require.Nil(t, client)
	require.EqualError(t, err, "keyID must specify a valid vault URL and key name")

	client, err = NewClient("https://myvault.vault.azure.net/keys/mykey", credential, nil)
	require.NotNil(t, client)
	require.Nil(t, err)
	require.Equal(t, "https://myvault.vault.azure.net/keys/mykey", client.KeyID())
}
