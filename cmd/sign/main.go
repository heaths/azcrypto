// Copyright 2023 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

package main

import (
	"context"
	"crypto"
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
	keyID     = flag.String("id", "", "Key ID used to sign.")
	message   = flag.String("m", "message", "The message to sign.")
	algorithm = flag.String("alg", string(azcrypto.SignatureAlgorithmES256), "The signing algorithm.")
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

	hash := getHash(*algorithm)
	if hash == 0 {
		log.Fatal("algorithm not supported")
	}

	h := hash.New()
	h.Write([]byte(*message))
	digest := h.Sum(nil)

	ctx := context.Background()
	signed, err := client.Sign(ctx, azcrypto.SignatureAlgorithm(*algorithm), digest, nil)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Plaintext: %s\n", *message)
	log.Printf("Digest: %x\n", digest)
	log.Printf("Key ID: %s\n", signed.KeyID)
	log.Printf("Signature: %x\n", signed.Signature)

	if *base64 {
		sig := b64.StdEncoding.EncodeToString(signed.Signature)
		log.Printf("Signature (base64): %s\n", sig)
	}
	if *base64url {
		sig := b64.RawURLEncoding.EncodeToString(signed.Signature)
		log.Printf("Signature (base64url): %s\n", sig)
	}

	verified, err := client.Verify(ctx, signed.Algorithm, digest, signed.Signature, nil)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Valid:", verified.Valid)
}

func getHash(algorithm string) crypto.Hash {
	switch azcrypto.SignatureAlgorithm(algorithm) {
	case azcrypto.SignatureAlgorithmPS256:
		fallthrough
	case azcrypto.SignatureAlgorithmRS256:
		fallthrough
	case azcrypto.SignatureAlgorithmES256:
		fallthrough
	case azcrypto.SignatureAlgorithmES256K:
		return crypto.SHA256

	case azcrypto.SignatureAlgorithmPS384:
		fallthrough
	case azcrypto.SignatureAlgorithmRS384:
		fallthrough
	case azcrypto.SignatureAlgorithmES384:
		return crypto.SHA384

	case azcrypto.SignatureAlgorithmPS512:
		fallthrough
	case azcrypto.SignatureAlgorithmRS512:
		fallthrough
	case azcrypto.SignatureAlgorithmES512:
		return crypto.SHA512

	default:
		return 0
	}
}
