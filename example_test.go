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

func ExampleClient_Sign() {
	hash := sha256.New()
	hash.Write([]byte("plaintext to sign"))
	digest := hash.Sum(nil)

	result, err := client.Sign(context.TODO(), azcrypto.SignatureAlgorithmES256, digest, nil)
	if err != nil {
		// TODO: handle error
	}

	fmt.Printf("%x\n", result.Signature)
}

func ExampleClient_SignData() {
	result, err := client.SignData(context.TODO(), azcrypto.SignatureAlgorithmES256, []byte("plaintext to sign"), nil)
	if err != nil {
		// TODO: handle error
	}

	fmt.Printf("%x\n", result.Signature)
}

func ExampleClient_Verify() {
	decoder := base64.RawURLEncoding
	signature, err := decoder.DecodeString("{raw base64url signature}")
	if err != nil {
		// TODO: handle error
	}

	result, err := client.VerifyData(context.TODO(), azcrypto.SignatureAlgorithmES256, []byte("plaintext to sign"), signature, nil)
	if err != nil {
		// TODO: handle error
	}

	fmt.Println(result.Valid)
}
