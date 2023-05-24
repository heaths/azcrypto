// Copyright 2023 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

package azcrypto_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
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

func ExampleClient_Encrypt() {
	result, err := client.Encrypt(context.TODO(), azcrypto.EncryptionAlgorithmRSAOAEP256, []byte("plaintext"), nil)
	if err != nil {
		// TODO: handle error
	}

	fmt.Printf("Ciphertext: %x\n", result.Ciphertext)
}

func ExampleClient_Decrypt() {
	decoder := base64.RawURLEncoding
	ciphertext, err := decoder.DecodeString("{base64url ciphertext}")
	if err != nil {
		// TODO: handle error
	}

	result, err := client.Decrypt(context.TODO(), azcrypto.EncryptionAlgorithmRSAOAEP256, ciphertext, nil)
	if err != nil {
		// TODO: handle error
	}

	fmt.Printf("Plaintext: %s\n", result.Plaintext)
}

func ExampleClient_Sign() {
	hash := sha256.New()
	hash.Write([]byte("plaintext"))
	digest := hash.Sum(nil)

	result, err := client.Sign(context.TODO(), azcrypto.SignatureAlgorithmES256, digest, nil)
	if err != nil {
		// TODO: handle error
	}

	fmt.Printf("Signature: %x\n", result.Signature)
}

func ExampleClient_SignData() {
	result, err := client.SignData(context.TODO(), azcrypto.SignatureAlgorithmES256, []byte("plaintext"), nil)
	if err != nil {
		// TODO: handle error
	}

	fmt.Printf("Signature: %x\n", result.Signature)
}

func ExampleClient_Verify() {
	decoder := base64.RawURLEncoding
	signature, err := decoder.DecodeString("{base64url signature}")
	if err != nil {
		// TODO: handle error
	}

	result, err := client.VerifyData(context.TODO(), azcrypto.SignatureAlgorithmES256, []byte("plaintext"), signature, nil)
	if err != nil {
		// TODO: handle error
	}

	fmt.Printf("Valid: %t\n", result.Valid)
}
