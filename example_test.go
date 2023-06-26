// Copyright 2023 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

package azcrypto_test

// cspell:ignore CwdwikXfzvz hpamtsb
import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/heaths/azcrypto"
)

var client *azcrypto.Client

func ExampleNewClient() {
	keyID := "https://{vault-name}.vault.azure.net/keys/{key-name}/{key-version}"
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		// TODO: handle error
	}

	client, err := azcrypto.NewClient(keyID, cred, nil)
	if err != nil {
		// TODO: handle error
	}

	_ = client
}

func ExampleNewClientFromJSONWebKey() {
	// Load an AES key encryption key (KEK) from a JWK.
	const jwk = `{
		"kty": "oct",
		"k": "vzZ5FtPDDpVJCwdwikXfzvz_3RAhWqGg7mcpPqPRlXk"
	}`

	var kek azkeys.JSONWebKey
	err := json.Unmarshal([]byte(jwk), &kek)
	if err != nil {
		// TODO: handle error
	}

	client, err := azcrypto.NewClientFromJSONWebKey(kek, nil)
	if err != nil {
		// TODO: handle error
	}

	_ = client
}

func ExampleClient_Encrypt() {
	result, err := client.Encrypt(context.TODO(), azcrypto.EncryptAlgorithmRSAOAEP256, []byte("plaintext"), nil)
	if err != nil {
		// TODO: handle error
	}

	fmt.Printf("Ciphertext: %x\n", result.Ciphertext)
}

// This example demonstrates how to encrypt plaintext using AES-CBC. The plaintext length must be a multiple of the
// key encryption key (KEK) block size. You can use PKCS7 padding if necessary.
//
// You should not use CBC without first ensuring the integrity of the ciphertext using an HMAC.
func ExampleClient_EncryptAESCBC() {
	// Use a unique initialization vector (IV) using a cryptographically random number generator for each block chain.
	// If nil, one will be generated for you using crypto/rand.Reader.
	var iv []byte

	// Plaintext length must be a multiple of the AES key encryption key (KEK) block size.
	// Use PKCS7 padding if necessary.
	plaintext, err := base64.StdEncoding.DecodeString("YWJjZGVmZ2hpamtsbW5vcA==")
	if err != nil {
		// TODO: handle error
	}

	result, err := client.EncryptAESCBC(context.TODO(), azcrypto.EncryptAESCBCAlgorithmA128CBC, plaintext, iv, nil)
	if err != nil {
		// TODO: handle error
	}

	// Common practice to prepend the IV (does not need to be secret) to the ciphertext.
	ciphertext := append(result.IV, result.Ciphertext...)
	fmt.Printf("IV + ciphertext: %s\n", base64.StdEncoding.EncodeToString(ciphertext))

	// Output:
	// IV + ciphertext: AAECAwQFBgcICQoLDA0OD3zQDBEoBTQX072KcqE9PwE=
}

// This example demonstrates how to encrypt plaintext using AES-CBC with an authenticating HMAC-SHA256.
// The plaintext length must be a multiple of the key encryption key (KEK) block size. You can use PKCS7 padding if necessary.
func ExampleClient_EncryptAESCBC_authenticated() {
	// Use a unique initialization vector (IV) using a cryptographically random number generator for each block chain.
	// If nil, one will be generated for you using crypto/rand.Reader.
	var iv []byte

	// Plaintext length must be a multiple of the AES key encryption key (KEK) block size.
	// Use PKCS7 padding if necessary.
	plaintext, err := base64.StdEncoding.DecodeString("YWJjZGVmZ2hpamtsbW5vcA==")
	if err != nil {
		// TODO: handle error
	}

	result, err := client.EncryptAESCBC(context.TODO(), azcrypto.EncryptAESCBCAlgorithmA128CBC, plaintext, iv, nil)
	if err != nil {
		// TODO: handle error
	}

	// Prepend the IV (does not need to be secret) to the ciphertext.
	ciphertext := append(result.IV, result.Ciphertext...)

	// Load your key for generating HMAC.
	key, err := base64.StdEncoding.DecodeString("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=")
	if err != nil {
		// TODO: handle error
	}

	h := hmac.New(sha256.New, key)
	h.Write(ciphertext)

	// Append the HMAC to the ciphertext.
	ciphertext = h.Sum(ciphertext)
	fmt.Printf("HMAC-SHA256(IV + ciphertext): %s\n", base64.StdEncoding.EncodeToString(ciphertext))

	// Output:
	// HMAC-SHA256(IV + ciphertext): AAECAwQFBgcICQoLDA0OD3zQDBEoBTQX072KcqE9PwEKzV0T+fWqPvkc8kRDtZPZDUJcCoH6T7l6EZtk1vZE2A==
}

func ExampleClient_EncryptAESGCM() {
	// Read plaintext and optional additional authenticated data (AAD).
	// AAD is not itself encrypted, but used in the encryption process and needs to be passed to DecryptAESGCM.
	plaintext := []byte("plaintext")
	var additionalAuthenticatedData []byte

	// A unique nonce will be generated using a cryptographically random number generator for each block chain.
	result, err := client.EncryptAESGCM(
		context.TODO(),
		azcrypto.EncryptAESGCMAlgorithmA128GCM,
		plaintext,
		additionalAuthenticatedData,
		nil,
	)
	if err != nil {
		// TODO: handle error
	}

	fmt.Printf("Ciphertext: %x\n", result.Ciphertext)
	fmt.Printf("Nonce: %x\n", result.Nonce)
	fmt.Printf("Authentication tag: %x\n", result.AuthenticationTag)

	// Output:
	// Ciphertext: fb6b11820810c6c5af
	// Nonce: 000102030405060708090a0b
	// Authentication tag: 22b2431748c3f81679ebe04f9d11fbae
}

func ExampleClient_Decrypt() {
	decoder := base64.RawURLEncoding
	ciphertext, err := decoder.DecodeString("{base64url ciphertext}")
	if err != nil {
		// TODO: handle error
	}

	result, err := client.Decrypt(context.TODO(), azcrypto.EncryptAlgorithmRSAOAEP256, ciphertext, nil)
	if err != nil {
		// TODO: handle error
	}

	fmt.Printf("Plaintext: %x\n", result.Plaintext)
}

// This example demonstrates how to decrypt using AES-CBC.
//
// You should not use CBC without first ensuring the integrity of the ciphertext using an HMAC.
func ExampleClient_DecryptAESCBC() {
	ciphertext, err := base64.StdEncoding.DecodeString("AAECAwQFBgcICQoLDA0OD3zQDBEoBTQX072KcqE9PwE=")
	if err != nil {
		// TODO: handle error
	}

	// Common practice is to prepend the unique IV for each block chain to the ciphertext.
	// Reverse what we did in the corresponding encryption example.
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	result, err := client.DecryptAESCBC(context.TODO(), azcrypto.EncryptAESCBCAlgorithmA128CBC, ciphertext, iv, nil)
	if err != nil {
		// TODO: handle error
	}

	fmt.Printf("Plaintext: %s\n", base64.StdEncoding.EncodeToString(result.Plaintext))

	// Output:
	// Plaintext: YWJjZGVmZ2hpamtsbW5vcA==
}

// This example demonstrates how to decrypt ciphertext using AES-CBC with an authenticating HMAC-SHA256.
func ExampleClient_DecryptAESCBC_authenticated() {
	ciphertext, err := base64.StdEncoding.DecodeString("AAECAwQFBgcICQoLDA0OD3zQDBEoBTQX072KcqE9PwEKzV0T+fWqPvkc8kRDtZPZDUJcCoH6T7l6EZtk1vZE2A==")
	if err != nil {
		// TODO: handle error
	}

	// Get the SHA256 hash from the end of the ciphertext we appended in the corresponding encryption example.
	signature := ciphertext[len(ciphertext)-sha256.Size:]
	ciphertext = ciphertext[:len(ciphertext)-sha256.Size]

	// Load your key for generating HMAC.
	key, err := base64.StdEncoding.DecodeString("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=")
	if err != nil {
		// TODO: handle error
	}

	// Compute the signature and compare with our extracted signature.
	h := hmac.New(sha256.New, key)
	h.Write(ciphertext)
	if !bytes.Equal(signature, h.Sum(nil)) {
		// TODO: handle error
	}

	// Common practice is to prepend the unique IV for each block chain to the ciphertext.
	// Reverse what we did in the corresponding encryption example.
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	result, err := client.DecryptAESCBC(context.TODO(), azcrypto.EncryptAESCBCAlgorithmA128CBC, ciphertext, iv, nil)
	if err != nil {
		// TODO: handle error
	}

	fmt.Printf("Plaintext: %s\n", base64.StdEncoding.EncodeToString(result.Plaintext))

	// Output:
	// Plaintext: YWJjZGVmZ2hpamtsbW5vcA==
}

func ExampleClient_DecryptAESGCM() {
	// Read ciphertext, nonce, and authentication tag, along with optional additional authenticated data (AAD).
	// AAD is not itself encrypted, but used in the encryption process and needs to be passed to DecryptAESGCM.
	ciphertext, err := hex.DecodeString("fb6b11820810c6c5af")
	if err != nil {
		// TODO: handle error
	}
	nonce, err := hex.DecodeString("000102030405060708090a0b")
	if err != nil {
		// TODO: handle error
	}
	authenticationTag, err := hex.DecodeString("22b2431748c3f81679ebe04f9d11fbae")
	if err != nil {
		// TODO: handle error
	}
	var additionalAuthenticatedData []byte

	result, err := client.DecryptAESGCM(
		context.TODO(),
		azcrypto.EncryptAESGCMAlgorithmA128GCM,
		ciphertext,
		nonce,
		authenticationTag,
		additionalAuthenticatedData,
		nil,
	)
	if err != nil {
		// TODO: handle error
	}

	fmt.Printf("Plaintext: %s\n", result.Plaintext)

	// Output:
	// Plaintext: plaintext
}

func ExampleClient_Sign() {
	hash := sha256.New()
	hash.Write([]byte("plaintext"))
	digest := hash.Sum(nil)

	result, err := client.Sign(context.TODO(), azcrypto.SignAlgorithmES256, digest, nil)
	if err != nil {
		// TODO: handle error
	}

	fmt.Printf("Signature: %x\n", result.Signature)
}

func ExampleClient_SignData() {
	result, err := client.SignData(context.TODO(), azcrypto.SignAlgorithmES256, []byte("plaintext"), nil)
	if err != nil {
		// TODO: handle error
	}

	fmt.Printf("Signature: %x\n", result.Signature)
}

func ExampleClient_WrapKey() {
	// Generate AES-256 key using a cryptographically secure RNG.
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		// TODO: handle error
	}

	// Encrypt the key using RSA-OAEP-256 to be stored securely.
	result, err := client.WrapKey(context.TODO(), azcrypto.WrapKeyAlgorithmRSAOAEP256, key, nil)
	if err != nil {
		// TODO: handle error
	}

	fmt.Printf("Encrypted key: %x\n", result.EncryptedKey)
}

func ExampleClient_UnwrapKey() {
	decoder := base64.RawURLEncoding
	encryptedKey, err := decoder.DecodeString("{base64url key}")
	if err != nil {
		// TODO: handle error
	}

	// Decrypt the key for use as a block cipher for e.g., streaming data.
	result, err := client.UnwrapKey(context.TODO(), azcrypto.WrapKeyAlgorithmRSAOAEP256, encryptedKey, nil)
	if err != nil {
		// TODO: handle error
	}

	fmt.Printf("Decrypted key: %x\n", result.Key)
}

func ExampleClient_Verify() {
	decoder := base64.RawURLEncoding
	signature, err := decoder.DecodeString("{base64url signature}")
	if err != nil {
		// TODO: handle error
	}

	result, err := client.VerifyData(context.TODO(), azcrypto.SignAlgorithmES256, []byte("plaintext"), signature, nil)
	if err != nil {
		// TODO: handle error
	}

	fmt.Printf("Valid: %t\n", result.Valid)
}

func init() {
	// Use an AES local client for deterministic output.
	const jwk = `{
		"kty": "oct",
		"k": "vzZ5FtPDDpVJCwdwikXfzvz_3RAhWqGg7mcpPqPRlXk"
	}`

	var kek azkeys.JSONWebKey
	err := json.Unmarshal([]byte(jwk), &kek)
	if err != nil {
		panic(err)
	}

	options := azcrypto.ClientOptions{
		// WARNING: for testing purposes only. Use crypto/rand.Reader (default).
		Rand: new(rng),
	}
	client, err = azcrypto.NewClientFromJSONWebKey(kek, &options)
	if err != nil {
		panic(err)
	}

}

// rng is a mock RNG used only for testing.
type rng struct{}

func (r *rng) Read(b []byte) (int, error) {
	for i := range b {
		b[i] = byte(i)
	}
	return len(b), nil
}
