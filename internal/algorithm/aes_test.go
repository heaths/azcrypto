// Copyright 2023 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

package algorithm

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/stretchr/testify/require"
)

func TestNewAES(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		key       azkeys.JSONWebKey
		keyID     string
		blockSize int
		errMsg    string
	}{
		{
			name: "unsupported kty",
			key: azkeys.JSONWebKey{
				Kty: to.Ptr(azkeys.JSONWebKeyTypeRSA),
			},
			errMsg: `AES does not support key type "RSA"`,
		},
		{
			name: "missing k",
			key: azkeys.JSONWebKey{
				Kty: to.Ptr(azkeys.JSONWebKeyTypeOct),
			},
			errMsg: `key unavailable`,
		},
		{
			name: "aes-128",
			key: azkeys.JSONWebKey{
				Kty: to.Ptr(azkeys.JSONWebKeyTypeOct),
				KID: to.Ptr(azkeys.ID("aes128")),
				K:   decodeBytes("9M09IArT3CEMYXEKBNdhgw=="), // cspell:disable-line
			},
			keyID:     "aes128",
			blockSize: 16,
		},
		{
			name: "aes-192",
			key: azkeys.JSONWebKey{
				Kty: to.Ptr(azkeys.JSONWebKeyTypeOct),
				KID: to.Ptr(azkeys.ID("aes192")),
				K:   decodeBytes("j47gBb9et5ytAdDV/YOOPke2DBjTLIOD"), // cspell:disable-line
			},
			keyID:     "aes192",
			blockSize: 16,
		},
		{
			name: "aes-256",
			key: azkeys.JSONWebKey{
				Kty: to.Ptr(azkeys.JSONWebKeyTypeOct),
				KID: to.Ptr(azkeys.ID("aes256")),
				K:   decodeBytes("vzZ5FtPDDpVJCwdwikXfzvz/3RAhWqGg7mcpPqPRlXk="), // cspell:disable-line
			},
			keyID:     "aes256",
			blockSize: 16,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			alg, err := newAES(tt.key)
			if tt.errMsg != "" {
				require.ErrorContains(t, err, tt.errMsg)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.keyID, alg.keyID)
			require.Equal(t, tt.blockSize, alg.block.BlockSize())
		})
	}
}

func TestAES_EncryptAESCBC(t *testing.T) {
	t.Parallel()

	src := []byte{0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70}
	iv := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
	tests := []struct {
		name      string
		kty       EncryptAESGCMAlgorithm
		plaintext []byte
		errMsg    string
	}{
		{
			name: "a128cbc",
			kty:  azkeys.JSONWebKeyEncryptionAlgorithmA128CBC,
		},
		{
			name: "a256cbc",
			kty:  azkeys.JSONWebKeyEncryptionAlgorithmA256CBC,
		},
		{
			name:      "invalid block size",
			kty:       azkeys.JSONWebKeyEncryptionAlgorithmA128CBC,
			plaintext: []byte("invalid"),
			errMsg:    "size of plaintext not a multiple of block size",
		},
		{
			name:   "unsupported",
			kty:    azkeys.JSONWebKeyEncryptionAlgorithmA128CBCPAD,
			errMsg: "operation not supported",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.plaintext == nil {

				tt.plaintext = make([]byte, aes.BlockSize)
				copy(tt.plaintext, src)
			}

			result, err := testAES.EncryptAESCBC(tt.kty, tt.plaintext, iv)
			if tt.errMsg != "" {
				require.ErrorContains(t, err, tt.errMsg)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.kty, result.Algorithm)
			require.Equal(t, "aes256", result.KeyID)
			require.Equal(t, iv, result.IV)
			require.Nil(t, result.Nonce)
			require.Nil(t, result.AdditionalAuthenticatedData)
			require.Nil(t, result.AuthenticationTag)

			dec := cipher.NewCBCDecrypter(testAES.block, result.IV)
			decrypted := make([]byte, len(tt.plaintext))
			dec.CryptBlocks(decrypted, result.Ciphertext)

			require.Equal(t, tt.plaintext, decrypted)
		})
	}
}

func TestAES_EncryptAESGCM(t *testing.T) {
	t.Parallel()

	nonce := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b}
	tests := []struct {
		name   string
		kty    EncryptAESGCMAlgorithm
		aad    []byte
		errMsg string
	}{
		{
			name: "a128gcm",
			kty:  azkeys.JSONWebKeyEncryptionAlgorithmA128GCM,
		},
		{
			name: "a256gcm with aad",
			kty:  azkeys.JSONWebKeyEncryptionAlgorithmA256GCM,
			aad:  []byte("additionalAuthenticatedData"),
		},
		{
			name:   "unsupported",
			kty:    azkeys.JSONWebKeyEncryptionAlgorithmA128CBC,
			errMsg: "operation not supported",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := testAES.EncryptAESGCM(tt.kty, []byte("plaintext"), nonce, tt.aad)
			if tt.errMsg != "" {
				require.ErrorContains(t, err, tt.errMsg)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.kty, result.Algorithm)
			require.Equal(t, "aes256", result.KeyID)
			require.Nil(t, result.IV)
			require.Equal(t, nonce, result.Nonce)
			require.Equal(t, tt.aad, result.AdditionalAuthenticatedData)
			require.NotNil(t, result.AuthenticationTag)

			gcm, err := cipher.NewGCM(testAES.block)
			require.NoError(t, err)

			// Append the ciphertext and tag how cipher.AEAD wants it.
			ciphertext := make([]byte, len(result.Ciphertext)+len(result.AuthenticationTag))
			copy(ciphertext[:len(result.Ciphertext)], result.Ciphertext)
			copy(ciphertext[len(result.Ciphertext):], result.AuthenticationTag)

			plaintext, err := gcm.Open(nil, nonce, ciphertext, result.AdditionalAuthenticatedData)
			require.NoError(t, err)
			require.Equal(t, []byte("plaintext"), plaintext)
		})
	}
}

func TestAES_WrapKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		alg        WrapKeyAlgorithm
		plaintext  string
		ciphertext string
		errMsg     string
	}{
		{
			name:       "A128KW",
			alg:        azkeys.JSONWebKeyEncryptionAlgorithmA128KW,
			plaintext:  "00112233445566778899AABBCCDDEEFF",
			ciphertext: "f41d33f9b9a7ea0bf3645432c8c89dc4f1be8cc32408a933",
		},
		{
			name:      "invalid",
			alg:       azkeys.JSONWebKeyEncryptionAlgorithmA128KW,
			plaintext: "00112233",
			errMsg:    "length of plaintext not multiple of 64 bits",
		},
		{
			name:   "unsupported",
			alg:    azkeys.JSONWebKeyEncryptionAlgorithmA128CBC,
			errMsg: "operation not supported",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plaintext, err := hex.DecodeString(tt.plaintext)
			require.NoError(t, err)
			ciphertext, err := hex.DecodeString(tt.ciphertext)
			require.NoError(t, err)

			result, err := testAES.WrapKey(tt.alg, plaintext)
			if tt.errMsg != "" {
				require.ErrorContains(t, err, tt.errMsg)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.alg, result.Algorithm)
			require.Equal(t, "aes256", result.KeyID)
			require.Equal(t, ciphertext, result.EncryptedKey)
		})
	}
}

func TestAESGenerateIV(t *testing.T) {
	t.Parallel()

	seed := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
	rand := bytes.NewBuffer(seed)

	iv, err := AESGenerateIV(rand)
	require.NoError(t, err)
	require.Equal(t, seed, iv)
}

func TestAESGenerateNonce(t *testing.T) {
	t.Parallel()

	seed := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b}
	rand := bytes.NewBuffer(seed)

	nonce, err := AESGenerateNonce(rand)
	require.NoError(t, err)
	require.Equal(t, seed, nonce)
}

func TestWrap(t *testing.T) {
	tests := []struct {
		name       string
		kek        string
		plaintext  string
		ciphertext string
		errMsg     string
	}{
		{
			name:       "wrap 128 bits of plaintext with 128-bit kek",
			kek:        "000102030405060708090A0B0C0D0E0F",
			plaintext:  "00112233445566778899AABBCCDDEEFF",
			ciphertext: "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5",
		},
		{
			name:       "wrap 128 bits of plaintext with 192-bit kek",
			kek:        "000102030405060708090A0B0C0D0E0F1011121314151617",
			plaintext:  "00112233445566778899AABBCCDDEEFF",
			ciphertext: "96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D",
		},
		{
			name:       "wrap 128 bits of plaintext with 256-bit kek",
			kek:        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
			plaintext:  "00112233445566778899AABBCCDDEEFF",
			ciphertext: "64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7",
		},
		{
			name:       "wrap 192 bits of plaintext with 192-bit kek",
			kek:        "000102030405060708090A0B0C0D0E0F1011121314151617",
			plaintext:  "00112233445566778899AABBCCDDEEFF0001020304050607",
			ciphertext: "031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2",
		},
		{
			name:       "wrap 192 bits of plaintext with 256-bit kek",
			kek:        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
			plaintext:  "00112233445566778899AABBCCDDEEFF0001020304050607",
			ciphertext: "A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1",
		},
		{
			name:       "wrap 256 bits of plaintext with 256-bit kek",
			kek:        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
			plaintext:  "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F",
			ciphertext: "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21",
		},
		{
			name:      "invalid",
			kek:       "000102030405060708090A0B0C0D0E0F",
			plaintext: "00112233",
			errMsg:    "length of plaintext not multiple of 64 bits",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kek, err := hex.DecodeString(tt.kek)
			require.NoError(t, err)
			plaintext, err := hex.DecodeString(tt.plaintext)
			require.NoError(t, err)
			expected, err := hex.DecodeString(tt.ciphertext)
			require.NoError(t, err)

			block, err := aes.NewCipher(kek)
			require.NoError(t, err)

			ciphertext, err := wrap(block, plaintext)
			if tt.errMsg != "" {
				require.ErrorContains(t, err, tt.errMsg)
				return
			}
			require.NoError(t, err)
			require.Equal(t, expected, ciphertext)
		})
	}
}

func decodeBytes(src string) []byte {
	dst, err := base64.StdEncoding.DecodeString(src)
	if err != nil {
		panic(err)
	}
	return dst
}

var testAES AES

func init() {
	key := decodeBytes("vzZ5FtPDDpVJCwdwikXfzvz/3RAhWqGg7mcpPqPRlXk=") // cspell:disable-line
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	testAES = AES{
		keyID: "aes256",
		block: block,
	}
}
