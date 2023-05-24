// Copyright 2023 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

package main

import (
	"context"
	_ "crypto/sha256"
	_ "crypto/sha512"
	b64 "encoding/base64"
	"flag"
	"log"

	azlog "github.com/Azure/azure-sdk-for-go/sdk/azcore/log"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/heaths/azcrypto"
)

var (
	keyID     = flag.String("id", "", "Key ID used to encrypt.")
	message   = flag.String("m", "message", "The message to encrypt.")
	algorithm = flag.String("alg", string(azcrypto.EncryptionAlgorithmRSAOAEP256), "The encryption algorithm.")
	debug     = flag.Bool("debug", false, "show debug information")
	base64    = flag.Bool("base64", false, "show base64-encoded signature")
	base64url = flag.Bool("base64url", false, "sow base64url-encoded signature")
)

func main() {
	flag.Parse()

	if *debug {
		azlog.SetListener(func(evt azlog.Event, message string) {
			log.Printf("(%s) %s", evt, message)
		})
	} else {
		log.SetFlags(0)
	}

	if keyID == nil {
		log.Fatal("id is required")
	}

	credential, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatal(err)
	}

	client, err := azcrypto.NewClient(*keyID, credential, nil)
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()
	encrypted, err := client.Encrypt(ctx, azcrypto.EncryptionAlgorithm(*algorithm), []byte(*message), nil)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Plaintext: %s\n", *message)
	log.Printf("Key ID: %s\n", encrypted.KeyID)
	log.Printf("Ciphertext: %x\n", encrypted.Ciphertext)
	if *base64 {
		ciphertext := b64.StdEncoding.EncodeToString(encrypted.Ciphertext)
		log.Printf("Ciphertext (base64): %s\n", ciphertext)
	}
	if *base64url {
		ciphertext := b64.RawURLEncoding.EncodeToString(encrypted.Ciphertext)
		log.Printf("Ciphertext (base64url): %s\n", ciphertext)
	}

	decrypted, err := client.Decrypt(ctx, encrypted.Algorithm, encrypted.Ciphertext, nil)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Decrypted:", string(decrypted.Plaintext))
	if *base64 {
		plaintext := b64.StdEncoding.EncodeToString(decrypted.Plaintext)
		log.Printf("Decrypted (base64): %s\n", plaintext)
	}
	if *base64url {
		plaintext := b64.RawURLEncoding.EncodeToString(decrypted.Plaintext)
		log.Printf("Decrypted (base64url): %s\n", plaintext)
	}
}
