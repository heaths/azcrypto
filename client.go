// Copyright 2023 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

package azcrypto

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/heaths/azcrypto/internal"
	alg "github.com/heaths/azcrypto/internal/algorithm"
)

// Client defines helpful methods to perform cryptography operations against a specific keyID,
// which should be stored with your data and used to perform the reverse cryptographic operations.
type Client struct {
	keyID      string
	keyName    string
	keyVersion string

	options      *ClientOptions
	remoteClient *azkeys.Client
	localClient  any

	_init sync.Once
}

type ClientOptions struct {
	azkeys.ClientOptions

	remoteOnly bool
}

// NewClient creates a Client for a specified key ID. If the caller has permission to download the specified public key,
// supported cryptography operations are performed locally.
//
// The public key is fetched only once. If you use a key ID without a version (not generally recommended) and the key
// is rotated in Azure Key Vault or Managed HSM, a new version is not retrieved. It is recommended that you always
// specify a key ID with a version, however, or at least store the full key ID returned by the service with your data
// so you always know which key to use to reverse the operation e.g., you can decrypt data you previously encrypted.
func NewClient(keyID string, credential azcore.TokenCredential, options *ClientOptions) (*Client, error) {
	if options == nil {
		options = &ClientOptions{}
	}

	vaultURL, name, version := internal.ParseID(&keyID)
	if vaultURL == nil || name == nil {
		return nil, fmt.Errorf("keyID must specify a valid vault URL and key name")
	}
	if version == nil {
		version = to.Ptr("")
	}

	client, err := azkeys.NewClient(*vaultURL, credential, &options.ClientOptions)
	if err != nil {
		return nil, err
	}

	return &Client{
		keyID:        keyID,
		keyName:      *name,
		keyVersion:   *version,
		options:      options,
		remoteClient: client,
	}, nil
}

// NewClientFromJSONWebKey creates a Client from the given JSON Web Key (JWK).
// No attempt will be made to contact Azure Key Vault or Managed HSM.
// If the JWK does not have the key material necessary for an operation, an error will be returned.
func NewClientFromJSONWebKey(key azkeys.JSONWebKey, options *ClientOptions) (*Client, error) {
	if options == nil {
		options = &ClientOptions{}
	}

	var keyID string
	if key.KID != nil {
		keyID = string(*key.KID)
	}

	localClient, err := alg.NewAlgorithm(key)
	if err != nil {
		return nil, fmt.Errorf("bad key: %w", err)
	}

	client := &Client{
		keyID:       string(keyID),
		options:     options,
		localClient: localClient,
	}
	client._init.Do(func() {})

	return client, nil
}

// KeyID gets the key ID passed to NewClient.
func (client *Client) KeyID() string {
	return client.keyID
}

func (client *Client) init(ctx context.Context) {
	client._init.Do(func() {
		if client.options.remoteOnly {
			return
		}

		response, err := client.remoteClient.GetKey(ctx, client.keyName, client.keyVersion, nil)
		if err != nil {
			return
		}

		key := response.Key
		if key == nil {
			return
		}

		alg, err := alg.NewAlgorithm(*key)
		if err != nil {
			return
		}

		client.localClient = alg
	})
}

// EncryptOptions defines options for the Encrypt method.
type EncryptOptions struct {
	azkeys.EncryptOptions
}

// EncryptResult contains information returned by the Encrypt method.
type EncryptResult struct {
	// Algorithm is encryption algorithm used to encrypt.
	Algorithm EncryptAlgorithm

	// KeyID is the key ID used to encrypt. This key ID should be retained.
	KeyID string

	// Ciphertext is the encryption result.
	Ciphertext []byte
}

// Encrypt encrypts the plaintext using the specified algorithm.
func (client *Client) Encrypt(ctx context.Context, algorithm EncryptAlgorithm, plaintext []byte, options *EncryptOptions) (EncryptResult, error) {
	client.init(ctx)

	var encrypter alg.Encrypter
	if alg.As(client.localClient, &encrypter) {
		result, err := encrypter.Encrypt(algorithm, plaintext)
		if client.localOnly() || !errors.Is(err, internal.ErrUnsupported) {
			return EncryptResult{
				Algorithm:  result.Algorithm,
				KeyID:      result.KeyID,
				Ciphertext: result.Ciphertext,
			}, err
		}
	}

	parameters := azkeys.KeyOperationsParameters{
		Algorithm: &algorithm,
		Value:     plaintext,
	}

	if options == nil {
		options = &EncryptOptions{}
	}

	response, err := client.remoteClient.Encrypt(
		ctx,
		client.keyName,
		client.keyVersion,
		parameters,
		&options.EncryptOptions,
	)
	if err != nil {
		return EncryptResult{}, err
	}

	keyID := client.keyID
	if response.KID != nil {
		keyID = string(*response.KID)
	}

	result := EncryptResult{
		Algorithm:  algorithm,
		KeyID:      keyID,
		Ciphertext: response.Result,
	}

	return result, nil
}

// EncryptAESCBCOptions defines options for the EncryptAESCBC method.
type EncryptAESCBCOptions struct {
	azkeys.EncryptOptions

	// Rand represents a random number generator.
	// By default this is crypto/rand.Reader.
	Rand io.Reader
}

// EncryptAESCBCResult contains information returned by the EncryptAESCBC method.
type EncryptAESCBCResult struct {
	// Algorithm is encryption algorithm used to encrypt.
	Algorithm EncryptAlgorithm

	// KeyID is the key ID used to encrypt. This key ID should be retained.
	KeyID string

	// Ciphertext is the encryption result.
	Ciphertext []byte

	// IV is the initialization vector used to encrypt using AES-CBC.
	IV []byte
}

// EncryptAESCBC encrypts the plaintext using the specified algorithm and optional initialization vector (IV).
// If iv is nil, one will be generated from a cryptographically secure random number generator, or options.Rand if specified.
//
// You should not use CBC without first ensuring the integrity of the ciphertext using an HMAC.
func (client *Client) EncryptAESCBC(ctx context.Context, algorithm EncryptAESCBCAlgorithm, plaintext, iv []byte, options *EncryptAESCBCOptions) (EncryptAESCBCResult, error) {
	client.init(ctx)

	if options == nil {
		options = &EncryptAESCBCOptions{}
	}
	if iv == nil {
		if options.Rand == nil {
			options.Rand = rand.Reader
		}
		var err error
		iv, err = alg.AESGenerateIV(options.Rand)
		if err != nil {
			return EncryptAESCBCResult{}, fmt.Errorf("generate IV: %w", err)
		}
	}

	var encrypter alg.AESEncrypter
	if alg.As(client.localClient, &encrypter) {
		result, err := encrypter.EncryptAESCBC(algorithm, plaintext, iv)
		if client.localOnly() || !errors.Is(err, internal.ErrUnsupported) {
			return EncryptAESCBCResult{
				Algorithm:  result.Algorithm,
				KeyID:      result.KeyID,
				Ciphertext: result.Ciphertext,
				IV:         result.IV,
			}, err
		}
	}

	parameters := azkeys.KeyOperationsParameters{
		Algorithm: &algorithm,
		Value:     plaintext,
		IV:        iv,
	}

	response, err := client.remoteClient.Encrypt(
		ctx,
		client.keyName,
		client.keyVersion,
		parameters,
		&options.EncryptOptions,
	)
	if err != nil {
		return EncryptAESCBCResult{}, err
	}

	keyID := client.keyID
	if response.KID != nil {
		keyID = string(*response.KID)
	}

	result := EncryptAESCBCResult{
		Algorithm:  algorithm,
		KeyID:      keyID,
		Ciphertext: response.Result,
		IV:         response.IV,
	}

	return result, nil
}

// EncryptAESGCMOptions defines options for the EncryptAESGCM method.
type EncryptAESGCMOptions struct {
	azkeys.EncryptOptions

	// Rand represents a random number generator.
	// By default this is crypto/rand.Reader.
	Rand io.Reader
}

// EncryptAESGCMResult contains information returned by the EncryptAESGCM method.
type EncryptAESGCMResult struct {
	// Algorithm is encryption algorithm used to encrypt.
	Algorithm EncryptAlgorithm

	// KeyID is the key ID used to encrypt. This key ID should be retained.
	KeyID string

	// Ciphertext is the encryption result.
	Ciphertext []byte

	// Nonce is the nonce used to encrypt using AES-GCM.
	Nonce []byte

	// AdditionalAuthenticatedData passed to EncryptAESGCM.
	AdditionalAuthenticatedData []byte

	// AuthenticationTag returned from EncryptAESGCM.
	AuthenticationTag []byte
}

// EncryptAESGCM encrypts the plaintext using the specified algorithm and optional authenticated data which is not encrypted.
func (client *Client) EncryptAESGCM(ctx context.Context, algorithm EncryptAESCBCAlgorithm, plaintext, additionalAuthenticatedData []byte, options *EncryptAESGCMOptions) (EncryptAESGCMResult, error) {
	client.init(ctx)

	if options == nil {
		options = &EncryptAESGCMOptions{}
	}
	if options.Rand == nil {
		options.Rand = rand.Reader
	}

	var encrypter alg.AESEncrypter
	if alg.As(client.localClient, &encrypter) {
		nonce, err := alg.AESGenerateNonce(options.Rand)
		if err != nil {
			return EncryptAESGCMResult{}, nil
		}

		result, err := encrypter.EncryptAESGCM(algorithm, plaintext, nonce, additionalAuthenticatedData)
		if client.localOnly() || !errors.Is(err, internal.ErrUnsupported) {
			return EncryptAESGCMResult{
				Algorithm:                   result.Algorithm,
				KeyID:                       result.KeyID,
				Ciphertext:                  result.Ciphertext,
				Nonce:                       result.Nonce,
				AdditionalAuthenticatedData: result.AdditionalAuthenticatedData,
				AuthenticationTag:           result.AuthenticationTag,
			}, err
		}
	}

	parameters := azkeys.KeyOperationsParameters{
		Algorithm: &algorithm,
		Value:     plaintext,
		AAD:       additionalAuthenticatedData,
	}

	response, err := client.remoteClient.Encrypt(
		ctx,
		client.keyName,
		client.keyVersion,
		parameters,
		&options.EncryptOptions,
	)
	if err != nil {
		return EncryptAESGCMResult{}, err
	}

	keyID := client.keyID
	if response.KID != nil {
		keyID = string(*response.KID)
	}

	result := EncryptAESGCMResult{
		Algorithm:                   algorithm,
		KeyID:                       keyID,
		Ciphertext:                  response.Result,
		Nonce:                       response.IV,
		AdditionalAuthenticatedData: response.AdditionalAuthenticatedData,
		AuthenticationTag:           response.AuthenticationTag,
	}

	return result, nil
}

// DecryptOptions defines options for the Decrypt method.
type DecryptOptions struct {
	azkeys.DecryptOptions
}

// DecryptResult contains information returned by the Decrypt method.
type DecryptResult = alg.DecryptResult

// Decrypt decrypts the ciphertext using the specified algorithm.
func (client *Client) Decrypt(ctx context.Context, algorithm EncryptAlgorithm, ciphertext []byte, options *DecryptOptions) (DecryptResult, error) {
	// Decrypting requires access to a private key, which Key Vault does not provide by default.
	parameters := azkeys.KeyOperationsParameters{
		Algorithm: &algorithm,
		Value:     ciphertext,
	}

	if options == nil {
		options = &DecryptOptions{}
	}

	response, err := client.remoteClient.Decrypt(
		ctx,
		client.keyName,
		client.keyVersion,
		parameters,
		&options.DecryptOptions,
	)
	if err != nil {
		return DecryptResult{}, err
	}

	keyID := client.keyID
	if response.KID != nil {
		keyID = string(*response.KID)
	}

	result := DecryptResult{
		Algorithm: algorithm,
		KeyID:     keyID,
		Plaintext: response.Result,
	}

	return result, nil
}

// DecryptAESCBCOptions defines options for the DecryptAESCBC method.
type DecryptAESCBCOptions struct {
	azkeys.DecryptOptions
}

// DecryptAESCBCResult contains information returned by the DecryptAESCBC method.
type DecryptAESCBCResult = alg.DecryptResult

// DecryptAESCBC decrypts the ciphertext using the specified algorithm.
func (client *Client) DecryptAESCBC(ctx context.Context, algorithm EncryptAESCBCAlgorithm, ciphertext, iv []byte, options *DecryptAESCBCOptions) (DecryptAESCBCResult, error) {
	client.init(ctx)

	var encrypter alg.AESEncrypter
	if alg.As(client.localClient, &encrypter) {
		result, err := encrypter.DecryptAESCBC(algorithm, ciphertext, iv)
		if client.localOnly() || !errors.Is(err, internal.ErrUnsupported) {
			return DecryptAESCBCResult{
				Algorithm: result.Algorithm,
				KeyID:     result.KeyID,
				Plaintext: result.Plaintext,
			}, err
		}
	}

	parameters := azkeys.KeyOperationsParameters{
		Algorithm: &algorithm,
		Value:     ciphertext,
		IV:        iv,
	}

	if options == nil {
		options = &DecryptAESCBCOptions{}
	}

	response, err := client.remoteClient.Decrypt(
		ctx,
		client.keyName,
		client.keyVersion,
		parameters,
		&options.DecryptOptions,
	)
	if err != nil {
		return DecryptResult{}, err
	}

	keyID := client.keyID
	if response.KID != nil {
		keyID = string(*response.KID)
	}

	result := DecryptResult{
		Algorithm: algorithm,
		KeyID:     keyID,
		Plaintext: response.Result,
	}

	return result, nil
}

// DecryptAESGCMOptions defines options for the DecryptAESGCM method.
type DecryptAESGCMOptions struct {
	azkeys.DecryptOptions
}

// DecryptAESGCMResult contains information returned by the DecryptAESGCM method.
type DecryptAESGCMResult = alg.DecryptResult

// DecryptAESGCM decrypts the ciphertext using the specified algorithm.
func (client *Client) DecryptAESGCM(ctx context.Context, algorithm EncryptAESGCMAlgorithm, ciphertext, nonce, authenticationTag, additionalAuthenticatedData []byte, options *DecryptAESGCMOptions) (DecryptAESGCMResult, error) {
	client.init(ctx)

	var encrypter alg.AESEncrypter
	if alg.As(client.localClient, &encrypter) {
		result, err := encrypter.DecryptAESGCM(algorithm, ciphertext, nonce, authenticationTag, additionalAuthenticatedData)
		if client.localOnly() || !errors.Is(err, internal.ErrUnsupported) {
			return DecryptAESCBCResult{
				Algorithm: result.Algorithm,
				KeyID:     result.KeyID,
				Plaintext: result.Plaintext,
			}, err
		}
	}

	parameters := azkeys.KeyOperationsParameters{
		Algorithm: &algorithm,
		Value:     ciphertext,
		IV:        nonce,
		Tag:       authenticationTag,
		AAD:       additionalAuthenticatedData,
	}

	if options == nil {
		options = &DecryptAESGCMOptions{}
	}

	response, err := client.remoteClient.Decrypt(
		ctx,
		client.keyName,
		client.keyVersion,
		parameters,
		&options.DecryptOptions,
	)
	if err != nil {
		return DecryptResult{}, err
	}

	keyID := client.keyID
	if response.KID != nil {
		keyID = string(*response.KID)
	}

	result := DecryptResult{
		Algorithm: algorithm,
		KeyID:     keyID,
		Plaintext: response.Result,
	}

	return result, nil
}

// SignOptions defines options for the Sign method.
type SignOptions struct {
	azkeys.SignOptions
}

// SignResult contains information returned by the Sign method.
type SignResult = alg.SignResult

// Sign signs the specified digest using the specified algorithm.
func (client *Client) Sign(ctx context.Context, algorithm SignAlgorithm, digest []byte, options *SignOptions) (SignResult, error) {
	// Signing requires access to a private key, which Key Vault does not provide by default.
	parameters := azkeys.SignParameters{
		Algorithm: &algorithm,
		Value:     digest,
	}

	if options == nil {
		options = &SignOptions{}
	}

	response, err := client.remoteClient.Sign(
		ctx,
		client.keyName,
		client.keyVersion,
		parameters,
		&options.SignOptions,
	)
	if err != nil {
		return SignResult{}, err
	}

	keyID := client.keyID
	if response.KID != nil {
		keyID = string(*response.KID)
	}

	result := SignResult{
		Algorithm: algorithm,
		KeyID:     keyID,
		Signature: response.Result,
	}

	return result, nil
}

// SignDataOptions defines options for the SignData method.
type SignDataOptions struct {
	SignOptions
}

// SignData hashes the data using a suitable hash based on the specified algorithm.
func (client *Client) SignData(ctx context.Context, algorithm SignAlgorithm, data []byte, options *SignDataOptions) (SignResult, error) {
	hash, err := alg.GetHash(algorithm)
	if err != nil {
		return SignResult{}, err
	}

	h := hash.New()
	h.Write(data)
	digest := h.Sum(nil)

	if options == nil {
		options = &SignDataOptions{}
	}

	return client.Sign(ctx, algorithm, digest, &options.SignOptions)
}

// VerifyOptions defines options for the Verify method.
type VerifyOptions struct {
	azkeys.VerifyOptions
}

// VerifyResult contains information returned by the Verify method.
type VerifyResult = alg.VerifyResult

// Verify verifies that the specified digest is valid using the specified signature and algorithm.
func (client *Client) Verify(ctx context.Context, algorithm SignAlgorithm, digest, signature []byte, options *VerifyOptions) (VerifyResult, error) {
	client.init(ctx)

	var signer alg.Signer
	if alg.As(client.localClient, &signer) {
		result, err := signer.Verify(algorithm, digest, signature)
		if client.localOnly() || !errors.Is(err, internal.ErrUnsupported) {
			return result, err
		}
	}

	parameters := azkeys.VerifyParameters{
		Algorithm: &algorithm,
		Digest:    digest,
		Signature: signature,
	}

	if options == nil {
		options = &VerifyOptions{}
	}

	response, err := client.remoteClient.Verify(
		ctx,
		client.keyName,
		client.keyVersion,
		parameters,
		&options.VerifyOptions,
	)
	if err != nil {
		return VerifyResult{}, err
	}

	result := VerifyResult{
		Algorithm: algorithm,
		KeyID:     client.keyID,
		Valid:     *response.Value,
	}

	return result, nil
}

// VerifyDataOptions defines options for the VerifyData method.
type VerifyDataOptions struct {
	VerifyOptions
}

// VerifyData verifies the digest of the data is valid using a suitable hash based on the specified algorithm.
func (client *Client) VerifyData(ctx context.Context, algorithm SignAlgorithm, data, signature []byte, options *VerifyDataOptions) (VerifyResult, error) {
	hash, err := alg.GetHash(algorithm)
	if err != nil {
		return VerifyResult{}, err
	}

	h := hash.New()
	h.Write(data)
	digest := h.Sum(nil)

	if options == nil {
		options = &VerifyDataOptions{}
	}

	return client.Verify(ctx, algorithm, digest, signature, &options.VerifyOptions)
}

// WrapKeyOptions defines options for the WrapKey method.
type WrapKeyOptions struct {
	azkeys.WrapKeyOptions
}

// WrapKeyResult contains information returned by the WrapKey method.
type WrapKeyResult = alg.WrapKeyResult

// WrapKey encrypts the specified key using the specified algorithm. Asymmetric encryption is typically used to wrap a symmetric key used for streaming ciphers.
func (client *Client) WrapKey(ctx context.Context, algorithm WrapKeyAlgorithm, key []byte, options *WrapKeyOptions) (WrapKeyResult, error) {
	client.init(ctx)

	var keyWrapper alg.KeyWrapper
	if alg.As(client.localClient, &keyWrapper) {
		result, err := keyWrapper.WrapKey(algorithm, key)
		if client.localOnly() || !errors.Is(err, internal.ErrUnsupported) {
			return result, err
		}
	}

	parameters := azkeys.KeyOperationsParameters{
		Algorithm: &algorithm,
		Value:     key,
	}

	if options == nil {
		options = &WrapKeyOptions{}
	}

	response, err := client.remoteClient.WrapKey(
		ctx,
		client.keyName,
		client.keyVersion,
		parameters,
		&options.WrapKeyOptions,
	)
	if err != nil {
		return WrapKeyResult{}, err
	}

	keyID := client.keyID
	if response.KID != nil {
		keyID = string(*response.KID)
	}

	result := WrapKeyResult{
		Algorithm:    algorithm,
		KeyID:        keyID,
		EncryptedKey: response.Result,
	}

	return result, nil
}

// UnwrapKeyOptions defines options for the UnwrapKey method.
type UnwrapKeyOptions struct {
	azkeys.UnwrapKeyOptions
}

// UnwrapKeyResult contains information returned by the UnwrapKey method.
type UnwrapKeyResult = alg.UnwrapKeyResult

// UnwrapKey decrypts the specified key using the specified algorithm. Asymmetric decryption is typically used to unwrap a symmetric key used for streaming ciphers.
func (client *Client) UnwrapKey(ctx context.Context, algorithm WrapKeyAlgorithm, encryptedKey []byte, options *UnwrapKeyOptions) (UnwrapKeyResult, error) {
	client.init(ctx)

	var keyWrapper alg.KeyWrapper
	if alg.As(client.localClient, &keyWrapper) {
		result, err := keyWrapper.UnwrapKey(algorithm, encryptedKey)
		if client.localOnly() || !errors.Is(err, internal.ErrUnsupported) {
			return result, err
		}
	}

	parameters := azkeys.KeyOperationsParameters{
		Algorithm: &algorithm,
		Value:     encryptedKey,
	}

	if options == nil {
		options = &UnwrapKeyOptions{}
	}

	response, err := client.remoteClient.UnwrapKey(
		ctx,
		client.keyName,
		client.keyVersion,
		parameters,
		&options.UnwrapKeyOptions,
	)
	if err != nil {
		return UnwrapKeyResult{}, err
	}

	keyID := client.keyID
	if response.KID != nil {
		keyID = string(*response.KID)
	}

	result := UnwrapKeyResult{
		Algorithm: algorithm,
		KeyID:     keyID,
		Key:       response.Result,
	}

	return result, nil
}

func (c *Client) localOnly() bool {
	return c.remoteClient == nil
}
