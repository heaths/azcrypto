package main

import (
	"context"
	"crypto/sha256"
	"log"
	"os"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azkeys"
	"github.com/heaths/azcrypto"
)

func main() {
	keyID := os.Args[1]
	message := os.Args[2]

	credential, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatal(err)
	}

	client, err := azcrypto.NewClient(keyID, credential, nil)
	if err != nil {
		log.Fatal(err)
	}

	sha256 := sha256.New()
	sha256.Write([]byte(message))
	digest := sha256.Sum(nil)

	ctx := context.Background()
	signed, err := client.Sign(ctx, azkeys.JSONWebKeySignatureAlgorithmES256, digest, nil)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Message:", message)
	log.Printf("Digest: %x\n", digest)
	log.Printf("Signature: %x\n", signed.Signature)

	verified, err := client.Verify(ctx, signed.Algorithm, digest, signed.Signature, nil)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Valid:", verified.Valid)
}
