package azcrypto

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azkeys"
	"github.com/heaths/azcrypto/internal"
)

type Client struct {
	keyURL     string
	keyName    string
	keyVersion string

	options      *ClientOptions
	remoteClient *azkeys.Client
	localClient  algorithm

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
		keyURL:       keyID,
		keyName:      *name,
		keyVersion:   *version,
		options:      options,
		remoteClient: client,
	}, nil
}

// KeyID gets the key ID passed to NewClient.
func (client *Client) KeyID() string {
	return client.keyURL
}

func (client *Client) init(ctx context.Context) {
	client._init.Do(func() {
		if client.options.remoteOnly {
			return
		}

		// TODO: Download the key, check if the operation is supported, and initial a local client.
	})
}

type SignatureAlgorithm = azkeys.JSONWebKeySignatureAlgorithm
type SignOptions = azkeys.SignOptions

type SignResult struct {
	// Algorithm is algorithm used to sign.
	Algorithm azkeys.JSONWebKeySignatureAlgorithm

	// KeyID is the key ID used to sign. This key ID should be retained.
	KeyID string

	// Signature is a signed hash of the data.
	Signature []byte
}

// Sign signs the specified digest using the specified algorithm.
func (client *Client) Sign(ctx context.Context, algorithm SignatureAlgorithm, digest []byte, options *SignOptions) (SignResult, error) {
	client.init(ctx)

	if client.localClient != nil {
		result, err := client.localClient.Sign(algorithm, digest)
		if !errors.Is(err, internal.Unsupported) {
			return result, err
		}
	}

	parameters := azkeys.SignParameters{
		Algorithm: &algorithm,
		Value:     digest,
	}
	response, err := client.remoteClient.Sign(
		ctx,
		client.keyName,
		client.keyVersion,
		parameters,
		options,
	)
	if err != nil {
		return SignResult{}, err
	}

	result := SignResult{
		Algorithm: algorithm,
		KeyID:     string(*response.KID),
		Signature: response.Result,
	}

	return result, nil
}

type VerifyOptions = azkeys.VerifyOptions

type VerifyResult struct {
	// Algorithm is algorithm used to verify.
	Algorithm azkeys.JSONWebKeySignatureAlgorithm

	// KeyID is the key ID used to verify.
	KeyID string

	// Valid is true of the signature is valid.
	Valid bool
}

// Verify verifies that the specified digest is valid using the specified signature and algorithm.
func (client *Client) Verify(ctx context.Context, algorithm SignatureAlgorithm, digest, signature []byte, options *VerifyOptions) (VerifyResult, error) {
	client.init(ctx)

	if client.localClient != nil {
		result, err := client.localClient.Verify(algorithm, digest, signature)
		if !errors.Is(err, internal.Unsupported) {
			return result, err
		}
	}

	parameters := azkeys.VerifyParameters{
		Algorithm: &algorithm,
		Digest:    digest,
		Signature: signature,
	}
	response, err := client.remoteClient.Verify(
		ctx,
		client.keyName,
		client.keyVersion,
		parameters,
		options,
	)
	if err != nil {
		return VerifyResult{}, nil
	}

	result := VerifyResult{
		Algorithm: algorithm,
		KeyID:     client.keyURL,
		Valid:     *response.Value,
	}

	return result, nil
}
