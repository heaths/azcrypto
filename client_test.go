// Copyright 2023 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

// cspell:disable

package azcrypto

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/heaths/azcrypto/internal/test"
	"github.com/stretchr/testify/require"
)

func TestNewClient(t *testing.T) {
	credential := test.MockCredential

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

func TestClient_EncryptDecrypt(t *testing.T) {
	tests := []struct {
		name       string
		key        string
		alg        EncryptionAlgorithm
		permission bool
		err        error
	}{
		{
			name:       "RSA1_5",
			key:        "rsa2048",
			alg:        EncryptionAlgorithmRSA15,
			permission: true,
		},
		{
			name: "RSA1_5 (no permission)",
			key:  "rsa2048",
			alg:  EncryptionAlgorithmRSA15,
		},
		{
			name:       "RSA-OAEP",
			key:        "rsa2048",
			alg:        EncryptionAlgorithmRSAOAEP,
			permission: true,
		},
		{
			name: "RSA-OAEP (no permission)",
			key:  "rsa2048",
			alg:  EncryptionAlgorithmRSAOAEP,
		},
		{
			name:       "RSA-OAEP-256",
			key:        "rsa2048",
			alg:        EncryptionAlgorithmRSAOAEP256,
			permission: true,
		},
		{
			name: "RSA-OAEP-256 (no permission)",
			key:  "rsa2048",
			alg:  EncryptionAlgorithmRSAOAEP256,
		},
		{
			name: "missing",
			key:  "missing",
			alg:  EncryptionAlgorithmRSAOAEP,
			err: &azcore.ResponseError{
				StatusCode: 404,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := test.Recorded(t, testClient(t, tt.key, tt.permission))

			var plaintext = []byte("plaintext")
			encrypted, err := client.Encrypt(context.Background(), tt.alg, plaintext, nil)
			if tt.err != nil {
				if !test.RequireIfResponseError(t, err, tt.err) {
					require.ErrorIs(t, err, tt.err)
				}
				return
			}
			require.NoError(t, err)

			decrypted, err := client.Decrypt(context.Background(), tt.alg, encrypted.Ciphertext, nil)
			require.NoError(t, err)

			require.Equal(t, plaintext, decrypted.Plaintext)
		})
	}
}

func TestClient_SignVerify(t *testing.T) {
	type testData struct {
		name       string
		key        string
		alg        SignatureAlgorithm
		permission bool
		err        error
	}
	tests := []testData{
		{
			name: "missing",
			key:  "missing",
			alg:  SignatureAlgorithmES256,
			err: &azcore.ResponseError{
				StatusCode: 404,
			},
		},
	}

	keys := []struct {
		name string
		key  string
		alg  SignatureAlgorithm
	}{
		{
			name: "ES256",
			key:  "ec256",
			alg:  SignatureAlgorithmES256,
		},
		{
			name: "ES384",
			key:  "ec384",
			alg:  SignatureAlgorithmES384,
		},
		{
			name: "ES512",
			key:  "ec521",
			alg:  SignatureAlgorithmES512,
		},
		{
			name: "PS256",
			key:  "rsa2048",
			alg:  SignatureAlgorithmPS256,
		},
		{
			name: "RS512",
			key:  "rsa2048",
			alg:  SignatureAlgorithmRS512,
		},
	}

	for _, key := range keys {
		tests = append(tests, testData{
			name:       key.name,
			key:        key.key,
			alg:        key.alg,
			permission: true,
		})
		tests = append(tests, testData{
			name: fmt.Sprintf("%s (no permission)", key.name),
			key:  key.key,
			alg:  key.alg,
		})
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := test.Recorded(t, testClient(t, tt.key, tt.permission))

			var plaintext = []byte("plaintext")
			signed, err := client.SignData(context.Background(), tt.alg, plaintext, nil)
			if tt.err != nil {
				if !test.RequireIfResponseError(t, err, tt.err) {
					require.ErrorIs(t, err, tt.err)
				}
				return
			}
			require.NoError(t, err)

			verified, err := client.VerifyData(context.Background(), tt.alg, plaintext, signed.Signature, nil)
			require.NoError(t, err)

			require.True(t, verified.Valid)
		})
	}
}

func TestClient_WrapUnwrapKey(t *testing.T) {
	tests := []struct {
		name       string
		key        string
		alg        KeyWrapAlgorithm
		permission bool
		err        error
	}{
		{
			name:       "RSA1_5",
			key:        "rsa2048",
			alg:        KeyWrapAlgorithmRSA15,
			permission: true,
		},
		{
			name: "RSA1_5 (no permission)",
			key:  "rsa2048",
			alg:  KeyWrapAlgorithmRSA15,
		},
		{
			name:       "RSA-OAEP",
			key:        "rsa2048",
			alg:        KeyWrapAlgorithmRSAOAEP,
			permission: true,
		},
		{
			name: "RSA-OAEP (no permission)",
			key:  "rsa2048",
			alg:  EncryptionAlgorithmRSAOAEP,
		},
		{
			name:       "RSA-OAEP-256",
			key:        "rsa2048",
			alg:        KeyWrapAlgorithmRSAOAEP256,
			permission: true,
		},
		{
			name: "RSA-OAEP-256 (no permission)",
			key:  "rsa2048",
			alg:  KeyWrapAlgorithmRSAOAEP256,
		},
		{
			name: "missing",
			key:  "missing",
			alg:  KeyWrapAlgorithmRSAOAEP,
			err: &azcore.ResponseError{
				StatusCode: 404,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := test.Recorded(t, testClient(t, tt.key, tt.permission))

			key, err := base64.StdEncoding.DecodeString("XuzMCMA534jyOTYaJ+rYvw==")
			require.NoError(t, err)

			wrapped, err := client.WrapKey(context.Background(), tt.alg, key, nil)
			if tt.err != nil {
				if !test.RequireIfResponseError(t, err, tt.err) {
					require.ErrorIs(t, err, tt.err)
				}
				return
			}
			require.NoError(t, err)

			unwrapped, err := client.UnwrapKey(context.Background(), tt.alg, wrapped.EncryptedKey, nil)
			require.NoError(t, err)

			require.Equal(t, key, unwrapped.Key)
		})
	}
}

func testClient(t *testing.T, keyName string, permission bool) test.ClientFactory[Client] {
	return func(recording *test.Recording) (*Client, error) {
		keyID := fmt.Sprintf("https://test.vault.azure.net/keys/%s", keyName)
		if recording.IsPassthrough() {
			vaultURL := os.Getenv("AZURE_KEYVAULT_URL")
			require.NotEmpty(t, vaultURL)

			var err error
			keyID, err = test.URLJoinPath(vaultURL, "keys", keyName)
			require.NoError(t, err)
		}

		if !permission {
			recording.OverrideResponse(func(req *http.Request, resp *http.Response) (code int, body string) {
				if req.Method == "GET" && resp.StatusCode == 200 && strings.HasPrefix(req.URL.EscapedPath(), "/keys/") {
					code = 403
					body = `{"error":{"code":"Forbidden"}}`
				}
				return
			})
		}

		return NewClient(keyID, recording.GetCredential(), &ClientOptions{
			ClientOptions: azkeys.ClientOptions{
				ClientOptions: azcore.ClientOptions{
					Transport: recording.GetTransport(),
				},
			},
		})
	}
}
