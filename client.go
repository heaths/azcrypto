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

// EncryptionAlgorithm defines the encryption algorithms supported by Azure Key Vault or MAnaged HSM.
type EncryptionAlgorithm = alg.EncryptionAlgorithm

const (
	// EncryptionAlgorithmRSA15 uses RSA 1.5.
	EncryptionAlgorithmRSA15 EncryptionAlgorithm = azkeys.JSONWebKeyEncryptionAlgorithmRSA15

	// EncryptionAlgorithmRSAOAEP uses RSA-OAEP.
	EncryptionAlgorithmRSAOAEP EncryptionAlgorithm = azkeys.JSONWebKeyEncryptionAlgorithmRSAOAEP

	// EncryptionAlgorithmRSAOAEP256 uses RSA-OAEP-256.
	EncryptionAlgorithmRSAOAEP256 EncryptionAlgorithm = azkeys.JSONWebKeyEncryptionAlgorithmRSAOAEP256
)

// SignatureAlgorithm defines the signing algorithms supported by Azure Key Vault or Managed HSM.
type SignatureAlgorithm = alg.SignatureAlgorithm

const (
	// SignatureAlgorithmES256 uses the P-256 curve requiring a SHA-256 hash.
	SignatureAlgorithmES256 SignatureAlgorithm = azkeys.JSONWebKeySignatureAlgorithmES256

	// SignatureAlgorithmES256K uses the P-256K curve requiring a SHA-256 hash.
	SignatureAlgorithmES256K SignatureAlgorithm = azkeys.JSONWebKeySignatureAlgorithmES256K

	// SignatureAlgorithmES384 uses the P-384 curve requiring a SHA-384 hash.
	SignatureAlgorithmES384 SignatureAlgorithm = azkeys.JSONWebKeySignatureAlgorithmES384

	// SignatureAlgorithmES512 uses the P-521 curve requiring a SHA-512 hash.
	SignatureAlgorithmES512 SignatureAlgorithm = azkeys.JSONWebKeySignatureAlgorithmES512

	// SignatureAlgorithmPS256 uses RSASSA-PSS using a SHA-256 hash.
	SignatureAlgorithmPS256 SignatureAlgorithm = azkeys.JSONWebKeySignatureAlgorithmPS256

	// SignatureAlgorithmPS384 uses RSASSA-PSS using a SHA-384 hash.
	SignatureAlgorithmPS384 SignatureAlgorithm = azkeys.JSONWebKeySignatureAlgorithmPS384

	// SignatureAlgorithmPS512 uses RSASSA-PSS using a SHA-512 hash.
	SignatureAlgorithmPS512 SignatureAlgorithm = azkeys.JSONWebKeySignatureAlgorithmPS512

	// SignatureAlgorithmRS256 uses RSASSA-PKCS1-v1_5 using a SHA256 hash.
	SignatureAlgorithmRS256 SignatureAlgorithm = azkeys.JSONWebKeySignatureAlgorithmRS256

	// SignatureAlgorithmRS384 uses RSASSA-PKCS1-v1_5 using a SHA384 hash.
	SignatureAlgorithmRS384 SignatureAlgorithm = azkeys.JSONWebKeySignatureAlgorithmRS384

	// SignatureAlgorithmRS512 uses RSASSA-PKCS1-v1_5 using a SHA512 hash.
	SignatureAlgorithmRS512 SignatureAlgorithm = azkeys.JSONWebKeySignatureAlgorithmRS512
)

type KeyWrapAlgorithm = alg.KeyWrapAlgorithm

const (
	// KeyWrapAlgorithmRSA15 uses RSA 1.5.
	KeyWrapAlgorithmRSA15 KeyWrapAlgorithm = azkeys.JSONWebKeyEncryptionAlgorithmRSA15

	// KeyWrapAlgorithmRSAOAEP uses RSA-OAEP.
	KeyWrapAlgorithmRSAOAEP KeyWrapAlgorithm = azkeys.JSONWebKeyEncryptionAlgorithmRSAOAEP

	// KeyWrapAlgorithmRSAOAEP256 uses RSA-OAEP-256.
	KeyWrapAlgorithmRSAOAEP256 KeyWrapAlgorithm = azkeys.JSONWebKeyEncryptionAlgorithmRSAOAEP256
)

// EncryptOptions defines options for the Encrypt method.
type EncryptOptions struct {
	azkeys.EncryptOptions
}

// EncryptResult contains information returned by the Encrypt method.
type EncryptResult = alg.EncryptResult

// Encrypt encrypts the plaintext using the specified algorithm.
func (client *Client) Encrypt(ctx context.Context, algorithm EncryptionAlgorithm, plaintext []byte, options *EncryptOptions) (EncryptResult, error) {
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
		return EncryptResult{}, nil
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
func (client *Client) Decrypt(ctx context.Context, algorithm EncryptionAlgorithm, ciphertext []byte, options *DecryptOptions) (DecryptResult, error) {
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
func (client *Client) Sign(ctx context.Context, algorithm SignatureAlgorithm, digest []byte, options *SignOptions) (SignResult, error) {
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
func (client *Client) SignData(ctx context.Context, algorithm SignatureAlgorithm, data []byte, options *SignDataOptions) (SignResult, error) {
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
func (client *Client) Verify(ctx context.Context, algorithm SignatureAlgorithm, digest, signature []byte, options *VerifyOptions) (VerifyResult, error) {
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
		return VerifyResult{}, nil
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
func (client *Client) VerifyData(ctx context.Context, algorithm SignatureAlgorithm, data, signature []byte, options *VerifyDataOptions) (VerifyResult, error) {
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
