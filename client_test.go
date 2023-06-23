// Copyright 2023 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

// cspell:disable

package azcrypto

import (
	"bytes"
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
	t.Parallel()

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
		alg        EncryptAlgorithm
		permission bool
		err        error
	}{
		{
			name: "RSA1_5",
			key:  "rsa2048",
			alg:  EncryptAlgorithmRSA15,
		},
		{
			name:       "RSA1_5 local",
			key:        "rsa2048",
			alg:        EncryptAlgorithmRSA15,
			permission: true,
		},
		{
			name: "RSA-OAEP",
			key:  "rsa2048",
			alg:  EncryptAlgorithmRSAOAEP,
		},
		{
			name:       "RSA-OAEP local",
			key:        "rsa2048",
			alg:        EncryptAlgorithmRSAOAEP,
			permission: true,
		},
		{
			name: "RSA-OAEP-256",
			key:  "rsa2048",
			alg:  EncryptAlgorithmRSAOAEP256,
		},
		{
			name:       "RSA-OAEP-256 local",
			key:        "rsa2048",
			alg:        EncryptAlgorithmRSAOAEP256,
			permission: true,
		},
		{
			name: "missing",
			key:  "missing",
			alg:  EncryptAlgorithmRSAOAEP,
			err: &azcore.ResponseError{
				StatusCode: 404,
			},
		},
	}

	for _, tt := range tests {
		tt := tt
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
			require.Equal(t, tt.permission, client.localClient != nil)
		})
	}
}

func TestClient_EncryptDecryptAESCBC(t *testing.T) {
	requireManagedHSM(t)

	seed := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
	tests := []struct {
		name string
		key  string
		alg  EncryptAESCBCAlgorithm
		iv   []byte
		err  error
	}{
		{
			name: "missing",
			key:  "missing",
			alg:  EncryptAESCBCAlgorithmA128CBC,
			err: &azcore.ResponseError{
				StatusCode: 404,
			},
		},
		{
			name: "unsupported local",
			key:  "aes128",
			alg:  EncryptAESCBCAlgorithmA128CBCPAD,
		},
		{
			name: "a128cbc",
			key:  "aes128",
			alg:  EncryptAESCBCAlgorithmA128CBC,
		},
		{
			name: "a128cbc with iv",
			key:  "aes128",
			alg:  EncryptAESCBCAlgorithmA128CBC,
			iv:   seed,
		},
		{
			name: "a192cbc",
			key:  "aes192",
			alg:  EncryptAESCBCAlgorithmA192CBC,
		},
		{
			name: "a256cbc",
			key:  "aes256",
			alg:  EncryptAESCBCAlgorithmA256CBC,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			client := test.Recorded(t, testClient(t, tt.key, false))

			plaintext := []byte{0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70}
			encrypted, err := client.EncryptAESCBC(context.Background(), tt.alg, plaintext, tt.iv, &EncryptAESCBCOptions{
				Rand: bytes.NewBuffer(seed),
			})
			if tt.err != nil {
				if !test.RequireIfResponseError(t, err, tt.err) {
					require.ErrorIs(t, err, tt.err)
				}
				return
			}
			require.NoError(t, err)

			decrypted, err := client.DecryptAESCBC(context.Background(), tt.alg, encrypted.Ciphertext, encrypted.IV, nil)
			require.NoError(t, err)

			require.Equal(t, plaintext, decrypted.Plaintext)
			require.Nil(t, client.localClient)
		})
	}
}

func TestClient_EncryptDecryptAESGCM(t *testing.T) {
	requireManagedHSM(t)

	tests := []struct {
		name string
		key  string
		alg  EncryptAESGCMAlgorithm
		aad  []byte
		err  error
	}{
		{
			name: "missing",
			key:  "missing",
			alg:  EncryptAESGCMAlgorithmA128GCM,
			err: &azcore.ResponseError{
				StatusCode: 404,
			},
		},
		{
			name: "A128GCM",
			key:  "aes128",
			alg:  EncryptAESGCMAlgorithmA128GCM,
		},
		{
			name: "A128GCM with AAD",
			key:  "aes128",
			alg:  EncryptAESGCMAlgorithmA128GCM,
			aad:  []byte("aad"),
		},
		{
			name: "A192GCM",
			key:  "aes192",
			alg:  EncryptAESGCMAlgorithmA192GCM,
		},
		{
			name: "A256GCM",
			key:  "aes256",
			alg:  EncryptAESGCMAlgorithmA256GCM,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			client := test.Recorded(t, testClient(t, tt.key, false))

			plaintext := []byte("plaintext")
			encrypted, err := client.EncryptAESGCM(context.Background(), tt.alg, plaintext, tt.aad, nil)
			if tt.err != nil {
				if !test.RequireIfResponseError(t, err, tt.err) {
					require.ErrorIs(t, err, tt.err)
				}
				return
			}
			require.NoError(t, err)

			decrypted, err := client.DecryptAESGCM(
				context.Background(),
				tt.alg,
				encrypted.Ciphertext,
				encrypted.Nonce,
				encrypted.AuthenticationTag,
				encrypted.AdditionalAuthenticatedData,
				nil)
			require.NoError(t, err)

			require.Equal(t, plaintext, decrypted.Plaintext)
			require.Nil(t, client.localClient)
		})
	}
}

func TestClient_SignVerify(t *testing.T) {
	type testData struct {
		name       string
		key        string
		alg        SignAlgorithm
		permission bool
		err        error
	}
	tests := []testData{
		{
			name: "missing",
			key:  "missing",
			alg:  SignAlgorithmES256,
			err: &azcore.ResponseError{
				StatusCode: 404,
			},
		},
	}

	keys := []struct {
		name string
		key  string
		alg  SignAlgorithm
	}{
		{name: "ES256", key: "ec256", alg: SignAlgorithmES256},
		{name: "ES384", key: "ec384", alg: SignAlgorithmES384},
		{name: "ES512", key: "ec521", alg: SignAlgorithmES512},
		{name: "PS256", key: "rsa2048", alg: SignAlgorithmPS256},
		{name: "RS512", key: "rsa2048", alg: SignAlgorithmRS512},
	}

	for _, key := range keys {
		tests = append(tests, testData{
			name: key.name,
			key:  key.key,
			alg:  key.alg,
		})
		tests = append(tests, testData{
			name:       fmt.Sprintf("%s local", key.name),
			key:        key.key,
			alg:        key.alg,
			permission: true,
		})
	}

	for _, tt := range tests {
		tt := tt
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
			require.Equal(t, tt.permission, client.localClient != nil)
		})
	}
}

func TestClient_WrapUnwrapKey(t *testing.T) {
	tests := []struct {
		name       string
		key        string
		alg        WrapKeyAlgorithm
		permission bool
		err        error
	}{
		{
			name: "RSA1_5",
			key:  "rsa2048",
			alg:  WrapKeyAlgorithmRSA15,
		},
		{
			name:       "RSA1_5 local",
			key:        "rsa2048",
			alg:        WrapKeyAlgorithmRSA15,
			permission: true,
		},
		{
			name: "RSA-OAEP",
			key:  "rsa2048",
			alg:  WrapKeyAlgorithmRSAOAEP,
		},
		{
			name:       "RSA-OAEP local",
			key:        "rsa2048",
			alg:        WrapKeyAlgorithmRSAOAEP,
			permission: true,
		},
		{
			name: "RSA-OAEP-256",
			key:  "rsa2048",
			alg:  WrapKeyAlgorithmRSAOAEP256,
		},
		{
			name:       "RSA-OAEP-256 local",
			key:        "rsa2048",
			alg:        WrapKeyAlgorithmRSAOAEP256,
			permission: true,
		},
		{
			name: "A128KW",
			key:  "aes128",
			alg:  WrapKeyAlgorithmA128KW,
		},
		{
			name: "A192KW",
			key:  "aes192",
			alg:  WrapKeyAlgorithmA192KW,
		},
		{
			name: "A256KW",
			key:  "aes256",
			alg:  WrapKeyAlgorithmA256KW,
		},
		{
			name: "missing",
			key:  "missing",
			alg:  WrapKeyAlgorithmRSAOAEP,
			err: &azcore.ResponseError{
				StatusCode: 404,
			},
		},
	}

	for _, tt := range tests {
		tt := tt
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
			require.Equal(t, tt.permission, client.localClient != nil)
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
			remoteOnly: test.IsRemoteOnly(),
		})
	}
}

func requireManagedHSM(t *testing.T) {
	t.Helper()
	if os.Getenv("AZURE_KEYVAULT_URL") != "" {
		if os.Getenv("AZURE_MANAGEDHSM") == "" {
			t.Skip("Managed HSM has not been provisioned")
		}
	}
}
