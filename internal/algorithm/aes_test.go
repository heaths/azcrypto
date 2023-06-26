// Copyright 2023 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

package algorithm

import (
	"bytes"
	"crypto/aes"
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
				K:   base64ToBytes("9M09IArT3CEMYXEKBNdhgw=="), // cspell:disable-line
			},
			keyID:     "aes128",
			blockSize: 16,
		},
		{
			name: "aes-192",
			key: azkeys.JSONWebKey{
				Kty: to.Ptr(azkeys.JSONWebKeyTypeOct),
				KID: to.Ptr(azkeys.ID("aes192")),
				K:   base64ToBytes("j47gBb9et5ytAdDV/YOOPke2DBjTLIOD"), // cspell:disable-line
			},
			keyID:     "aes192",
			blockSize: 16,
		},
		{
			name: "aes-256",
			key: azkeys.JSONWebKey{
				Kty: to.Ptr(azkeys.JSONWebKeyTypeOct),
				KID: to.Ptr(azkeys.ID("aes256")),
				K:   base64ToBytes("vzZ5FtPDDpVJCwdwikXfzvz/3RAhWqGg7mcpPqPRlXk="), // cspell:disable-line
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

	iv := base64ToBytes("AAECAwQFBgcICQoLDA0ODw==") // cspell:disable-line
	tests := []struct {
		name       string
		kty        EncryptAESGCMAlgorithm
		plaintext  []byte
		ciphertext []byte
		errMsg     string
	}{
		{
			name:       "a128cbc",
			kty:        azkeys.JSONWebKeyEncryptionAlgorithmA128CBC,
			plaintext:  base64ToBytes("YWJjZGVmZ2hpamtsbW5vcA=="), // cspell:disable-line
			ciphertext: base64ToBytes("fNAMESgFNBfTvYpyoT0/AQ=="), // cspell:disable-line
		},
		{
			name:       "a256cbc",
			kty:        azkeys.JSONWebKeyEncryptionAlgorithmA256CBC,
			plaintext:  base64ToBytes("YWJjZGVmZ2hpamtsbW5vcA=="), // cspell:disable-line
			ciphertext: base64ToBytes("fNAMESgFNBfTvYpyoT0/AQ=="), // cspell:disable-line
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
			result, err := testAES.EncryptAESCBC(tt.kty, tt.plaintext, iv)
			if tt.errMsg != "" {
				require.ErrorContains(t, err, tt.errMsg)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.kty, result.Algorithm)
			require.Equal(t, "aes256", result.KeyID)
			require.Equal(t, iv, result.IV)
			require.Equal(t, tt.ciphertext, result.Ciphertext)
			require.Nil(t, result.Nonce)
			require.Nil(t, result.AdditionalAuthenticatedData)
			require.Nil(t, result.AuthenticationTag)
		})
	}
}

func TestAES_DecryptAESCBC(t *testing.T) {
	t.Parallel()

	iv := base64ToBytes("AAECAwQFBgcICQoLDA0ODw==") // cspell:disable-line
	tests := []struct {
		name       string
		kty        EncryptAESGCMAlgorithm
		plaintext  []byte
		ciphertext []byte
		errMsg     string
	}{
		{
			name:       "a128cbc",
			kty:        azkeys.JSONWebKeyEncryptionAlgorithmA128CBC,
			plaintext:  base64ToBytes("YWJjZGVmZ2hpamtsbW5vcA=="), // cspell:disable-line
			ciphertext: base64ToBytes("fNAMESgFNBfTvYpyoT0/AQ=="), // cspell:disable-line
		},
		{
			name:       "a256cbc",
			kty:        azkeys.JSONWebKeyEncryptionAlgorithmA256CBC,
			plaintext:  base64ToBytes("YWJjZGVmZ2hpamtsbW5vcA=="), // cspell:disable-line
			ciphertext: base64ToBytes("fNAMESgFNBfTvYpyoT0/AQ=="), // cspell:disable-line
		},
		{
			name:       "invalid block size",
			kty:        azkeys.JSONWebKeyEncryptionAlgorithmA128CBC,
			ciphertext: []byte("invalid"),
			errMsg:     "size of ciphertext not a multiple of block size",
		},
		{
			name:   "unsupported",
			kty:    azkeys.JSONWebKeyEncryptionAlgorithmA128CBCPAD,
			errMsg: "operation not supported",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := testAES.DecryptAESCBC(tt.kty, tt.ciphertext, iv)
			if tt.errMsg != "" {
				require.ErrorContains(t, err, tt.errMsg)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.kty, result.Algorithm)
			require.Equal(t, "aes256", result.KeyID)
			require.Equal(t, tt.plaintext, result.Plaintext)
		})
	}
}

func TestAES_EncryptAESGCM(t *testing.T) {
	t.Parallel()

	nonce := base64ToBytes("AAECAwQFBgcICQoL") // cspell:disable-line
	tests := []struct {
		name       string
		kty        EncryptAESGCMAlgorithm
		aad        []byte
		ciphertext []byte
		tag        []byte
		errMsg     string
	}{
		{
			name:       "a128gcm",
			kty:        azkeys.JSONWebKeyEncryptionAlgorithmA128GCM,
			ciphertext: base64ToBytes("+2sRgggQxsWv"),             // cspell:disable-line
			tag:        base64ToBytes("IrJDF0jD+BZ56+BPnRH7rg=="), // cspell:disable-line
		},
		{
			name:       "a256gcm with aad",
			kty:        azkeys.JSONWebKeyEncryptionAlgorithmA256GCM,
			aad:        []byte("additionalAuthenticatedData"),
			ciphertext: base64ToBytes("+2sRgggQxsWv"),             // cspell:disable-line
			tag:        base64ToBytes("Xora0uL34SJwoNUA5FOkAg=="), // cspell:disable-line
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
			require.Equal(t, tt.ciphertext, result.Ciphertext)
			require.Equal(t, nonce, result.Nonce)
			require.Equal(t, tt.aad, result.AdditionalAuthenticatedData)
			require.Equal(t, tt.tag, result.AuthenticationTag)
		})
	}
}

func TestAES_DecryptAESGCM(t *testing.T) {
	t.Parallel()

	nonce := base64ToBytes("AAECAwQFBgcICQoL") // cspell:disable-line
	tests := []struct {
		name       string
		kty        EncryptAESGCMAlgorithm
		aad        []byte
		ciphertext []byte
		tag        []byte
		errMsg     string
	}{
		{
			name:       "a128gcm",
			kty:        azkeys.JSONWebKeyEncryptionAlgorithmA128GCM,
			ciphertext: base64ToBytes("+2sRgggQxsWv"),             // cspell:disable-line
			tag:        base64ToBytes("IrJDF0jD+BZ56+BPnRH7rg=="), // cspell:disable-line
		},
		{
			name:       "a256gcm with aad",
			kty:        azkeys.JSONWebKeyEncryptionAlgorithmA256GCM,
			aad:        []byte("additionalAuthenticatedData"),
			ciphertext: base64ToBytes("+2sRgggQxsWv"),             // cspell:disable-line
			tag:        base64ToBytes("Xora0uL34SJwoNUA5FOkAg=="), // cspell:disable-line
		},
		{
			name:   "unsupported",
			kty:    azkeys.JSONWebKeyEncryptionAlgorithmA128CBC,
			errMsg: "operation not supported",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := testAES.DecryptAESGCM(tt.kty, tt.ciphertext, nonce, tt.tag, tt.aad)
			if tt.errMsg != "" {
				require.ErrorContains(t, err, tt.errMsg)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.kty, result.Algorithm)
			require.Equal(t, "aes256", result.KeyID)
			require.Equal(t, []byte("plaintext"), result.Plaintext)
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
			name:       "a128kw",
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
			plaintext := hexToBytes(tt.plaintext)
			ciphertext := hexToBytes(tt.ciphertext)

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

func TestAES_UnwrapKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		alg        WrapKeyAlgorithm
		plaintext  string
		ciphertext string
		errMsg     string
	}{
		{
			name:       "a128kw",
			alg:        azkeys.JSONWebKeyEncryptionAlgorithmA128KW,
			plaintext:  "00112233445566778899AABBCCDDEEFF",
			ciphertext: "f41d33f9b9a7ea0bf3645432c8c89dc4f1be8cc32408a933",
		},
		{
			name:       "invalid",
			alg:        azkeys.JSONWebKeyEncryptionAlgorithmA128KW,
			ciphertext: "00112233",
			errMsg:     "length of ciphertext not multiple of 64 bits",
		},
		{
			name:   "unsupported",
			alg:    azkeys.JSONWebKeyEncryptionAlgorithmA128CBC,
			errMsg: "operation not supported",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plaintext := hexToBytes(tt.plaintext)
			ciphertext := hexToBytes(tt.ciphertext)

			result, err := testAES.UnwrapKey(tt.alg, ciphertext)
			if tt.errMsg != "" {
				require.ErrorContains(t, err, tt.errMsg)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.alg, result.Algorithm)
			require.Equal(t, "aes256", result.KeyID)
			require.Equal(t, plaintext, result.Key)
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
	t.Parallel()

	tests := []struct {
		name       string
		kek        string
		plaintext  string
		ciphertext string
		errMsg     string
	}{
		// Test cases from https://www.rfc-editor.org/rfc/rfc3394.
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
			kek := hexToBytes(tt.kek)
			plaintext := hexToBytes(tt.plaintext)
			expected := hexToBytes(tt.ciphertext)

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

func TestUnwrap(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		kek        string
		plaintext  string
		ciphertext string
		errMsg     string
	}{
		// Test cases from https://www.rfc-editor.org/rfc/rfc3394.
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
			name:       "invalid",
			kek:        "000102030405060708090A0B0C0D0E0F",
			ciphertext: "00112233",
			errMsg:     "length of ciphertext not multiple of 64 bits",
		},
		{
			name:       "corrupt",
			kek:        "000102030405060708090A0B0C0D0E0F",
			ciphertext: "18C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21",
			errMsg:     "integrity check failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kek := hexToBytes(tt.kek)
			expected := hexToBytes(tt.plaintext)
			ciphertext := hexToBytes(tt.ciphertext)

			block, err := aes.NewCipher(kek)
			require.NoError(t, err)

			plaintext, err := unwrap(block, ciphertext)
			if tt.errMsg != "" {
				require.ErrorContains(t, err, tt.errMsg)
				return
			}
			require.NoError(t, err)
			require.Equal(t, expected, plaintext)
		})
	}
}

var testAES AES

func init() {
	key := base64ToBytes("vzZ5FtPDDpVJCwdwikXfzvz/3RAhWqGg7mcpPqPRlXk=") // cspell:disable-line
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	testAES = AES{
		keyID:   "aes256",
		block:   block,
		keySize: 32,
	}
}

func TestRequiresKeySize(t *testing.T) {
	t.Parallel()

	key := base64ToBytes("JQJjdiDye/kYCCsXmBWgGw==") // cspell:disable-line
	block, err := aes.NewCipher(key)
	require.NoError(t, err)

	a := AES{
		keyID:   "aes128",
		block:   block,
		keySize: 16,
	}
	iv := base64ToBytes("AAECAwQFBgcICQoLDA0ODw==") // cspell:disable-line

	_, err = a.EncryptAESCBC(azkeys.JSONWebKeyEncryptionAlgorithmA128CBC, nil, iv)
	require.NoError(t, err)

	_, err = a.EncryptAESCBC(azkeys.JSONWebKeyEncryptionAlgorithmA192CBC, nil, iv)
	require.ErrorContains(t, err, "A192CBC requires key size 24 bytes or larger")

	_, err = a.EncryptAESCBC(azkeys.JSONWebKeyEncryptionAlgorithmA256CBC, nil, iv)
	require.ErrorContains(t, err, "A256CBC requires key size 32 bytes or larger")

	_, err = a.EncryptAESGCM(azkeys.JSONWebKeyEncryptionAlgorithmA256GCM, nil, iv, nil)
	require.ErrorContains(t, err, "A256GCM requires key size 32 bytes or larger")

	_, err = a.DecryptAESCBC(azkeys.JSONWebKeyEncryptionAlgorithmA256CBC, nil, iv)
	require.ErrorContains(t, err, "A256CBC requires key size 32 bytes or larger")

	_, err = a.DecryptAESGCM(azkeys.JSONWebKeyEncryptionAlgorithmA256GCM, nil, iv, nil, nil)
	require.ErrorContains(t, err, "A256GCM requires key size 32 bytes or larger")

	_, err = a.WrapKey(azkeys.JSONWebKeyEncryptionAlgorithmA256KW, nil)
	require.ErrorContains(t, err, "A256KW requires key size 32 bytes or larger")
}

func TestXorBytes(t *testing.T) {
	t.Parallel()

	dst := make([]byte, 2)

	xorBytes(dst, []byte{}, []byte{})
	require.Equal(t, dst, []byte{0x00, 0x00})

	xorBytes(dst, []byte{0x00, 0x01}, []byte{0x01})
	require.Equal(t, []byte{0x01, 0x00}, dst)

	xorBytes(dst, []byte{0x00}, []byte{0x01, 0x01})
	require.Equal(t, []byte{0x01, 0x00}, dst)

	require.Panics(t, func() {
		xorBytes(dst, []byte{0x00, 0x01, 0x02}, []byte{0x00, 0x01, 0x02})
	})
}
