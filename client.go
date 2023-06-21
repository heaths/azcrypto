// Copyright 2023 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

package azcrypto

// TODO: Remove calls to log throughout this module.

import (
	"context"
	"errors"
	"fmt"
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
	localClient  alg.Algorithm

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
type EncryptResult = alg.EncryptResult

// Encrypt encrypts the plaintext using the specified algorithm.
func (client *Client) Encrypt(ctx context.Context, algorithm EncryptAlgorithm, plaintext []byte, options *EncryptOptions) (EncryptResult, error) {
	client.init(ctx)

	if client.localClient != nil {
		result, err := client.localClient.Encrypt(algorithm, plaintext)
		if !errors.Is(err, internal.ErrUnsupported) {
			return result, err
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

	if client.localClient != nil {
		result, err := client.localClient.Verify(algorithm, digest, signature)
		if !errors.Is(err, internal.ErrUnsupported) {
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

	if client.localClient != nil {
		result, err := client.localClient.WrapKey(algorithm, key)
		if !errors.Is(err, internal.ErrUnsupported) {
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
	// Unwrapping a key requires access to a private key, which Key Vault does not provide by default.
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
