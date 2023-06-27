// Copyright 2023 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

package azcrypto

import (
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	alg "github.com/heaths/azcrypto/internal/algorithm"
)

// EncryptAlgorithm defines the encryption algorithms supported by Azure Key Vault or Managed HSM.
type EncryptAlgorithm = alg.EncryptAlgorithm

const (
	// EncryptAlgorithmRSA15 uses RSA 1.5.
	EncryptAlgorithmRSA15 EncryptAlgorithm = azkeys.EncryptionAlgorithmRSA15

	// EncryptAlgorithmRSAOAEP uses RSA-OAEP.
	EncryptAlgorithmRSAOAEP EncryptAlgorithm = azkeys.EncryptionAlgorithmRSAOAEP

	// EncryptAlgorithmRSAOAEP256 uses RSA-OAEP-256.
	EncryptAlgorithmRSAOAEP256 EncryptAlgorithm = azkeys.EncryptionAlgorithmRSAOAEP256
)

// EncryptAESCBCAlgorithm defines the encryption algorithms supported by Azure Managed HSM for encryption with AES-CBC.
//
// You should not use CBC without first ensuring the integrity of the ciphertext using an HMAC.
type EncryptAESCBCAlgorithm = alg.EncryptAESCBCAlgorithm

const (
	// EncryptAESCBCAlgorithmA128CBC uses A128-CBC with a message length appropriately padded to a multiple of 16 bytes.
	//
	// You should not use CBC without first ensuring the integrity of the ciphertext using an HMAC.
	EncryptAESCBCAlgorithmA128CBC EncryptAESCBCAlgorithm = azkeys.EncryptionAlgorithmA128CBC

	// EncryptAESCBCAlgorithmA128CBC uses A128-CBCPAD to pad a message using PKCS7 to a multiple of 16 bytes.
	//
	// You should not use CBC without first ensuring the integrity of the ciphertext using an HMAC.
	EncryptAESCBCAlgorithmA128CBCPAD EncryptAESCBCAlgorithm = azkeys.EncryptionAlgorithmA128CBCPAD

	// EncryptAESCBCAlgorithmA192CBC uses A192-CBC with a message length appropriately padded to a multiple of 16 bytes.
	//
	// You should not use CBC without first ensuring the integrity of the ciphertext using an HMAC.
	EncryptAESCBCAlgorithmA192CBC EncryptAESCBCAlgorithm = azkeys.EncryptionAlgorithmA192CBC

	// EncryptAESCBCAlgorithmA192CBC uses A192-CBCPAD to pad a message using PKCS7 to a multiple of 16 bytes.
	//
	// You should not use CBC without first ensuring the integrity of the ciphertext using an HMAC.
	EncryptAESCBCAlgorithmA192CBCPAD EncryptAESCBCAlgorithm = azkeys.EncryptionAlgorithmA192CBCPAD

	// EncryptAESCBCAlgorithmA256CBC uses A256-CBC with a message length appropriately padded to a multiple of 16 bytes.
	//
	// You should not use CBC without first ensuring the integrity of the ciphertext using an HMAC.
	EncryptAESCBCAlgorithmA256CBC EncryptAESCBCAlgorithm = azkeys.EncryptionAlgorithmA256CBC

	// EncryptAESCBCAlgorithmA256CBC uses A256-CBCPAD to pad a message using PKCS7 to a multiple of 16 bytes.
	//
	// You should not use CBC without first ensuring the integrity of the ciphertext using an HMAC.
	EncryptAESCBCAlgorithmA256CBCPAD EncryptAESCBCAlgorithm = azkeys.EncryptionAlgorithmA256CBCPAD
)

// EncryptAESGCMAlgorithm defines the encryption algorithms supported by Azure Managed HSM for encryption with AES-GCM.
type EncryptAESGCMAlgorithm = alg.EncryptAESGCMAlgorithm

const (
	// EncryptAESGCMAlgorithmA128GCM uses A128-GCM with optional authenticated data.
	EncryptAESGCMAlgorithmA128GCM EncryptAESGCMAlgorithm = azkeys.EncryptionAlgorithmA128GCM

	// EncryptAESGCMAlgorithmA192GCM uses A192-GCM with optional authenticated data.
	EncryptAESGCMAlgorithmA192GCM EncryptAESGCMAlgorithm = azkeys.EncryptionAlgorithmA192GCM

	// EncryptAESGCMAlgorithmA256GCM uses A256-GCM with optional authenticated data.
	EncryptAESGCMAlgorithmA256GCM EncryptAESGCMAlgorithm = azkeys.EncryptionAlgorithmA256GCM
)

// SignAlgorithm defines the signing algorithms supported by Azure Key Vault or Managed HSM.
type SignAlgorithm = alg.SignAlgorithm

const (
	// SignAlgorithmES256 uses the P-256 curve requiring a SHA-256 hash.
	SignAlgorithmES256 SignAlgorithm = azkeys.SignatureAlgorithmES256

	// SignAlgorithmES256K uses the P-256K curve requiring a SHA-256 hash.
	SignAlgorithmES256K SignAlgorithm = azkeys.SignatureAlgorithmES256K

	// SignAlgorithmES384 uses the P-384 curve requiring a SHA-384 hash.
	SignAlgorithmES384 SignAlgorithm = azkeys.SignatureAlgorithmES384

	// SignAlgorithmES512 uses the P-521 curve requiring a SHA-512 hash.
	SignAlgorithmES512 SignAlgorithm = azkeys.SignatureAlgorithmES512

	// SignAlgorithmPS256 uses RSASSA-PSS using a SHA-256 hash.
	SignAlgorithmPS256 SignAlgorithm = azkeys.SignatureAlgorithmPS256

	// SignAlgorithmPS384 uses RSASSA-PSS using a SHA-384 hash.
	SignAlgorithmPS384 SignAlgorithm = azkeys.SignatureAlgorithmPS384

	// SignAlgorithmPS512 uses RSASSA-PSS using a SHA-512 hash.
	SignAlgorithmPS512 SignAlgorithm = azkeys.SignatureAlgorithmPS512

	// SignAlgorithmRS256 uses RSASSA-PKCS1-v1_5 using a SHA256 hash.
	SignAlgorithmRS256 SignAlgorithm = azkeys.SignatureAlgorithmRS256

	// SignAlgorithmRS384 uses RSASSA-PKCS1-v1_5 using a SHA384 hash.
	SignAlgorithmRS384 SignAlgorithm = azkeys.SignatureAlgorithmRS384

	// SignAlgorithmRS512 uses RSASSA-PKCS1-v1_5 using a SHA512 hash.
	SignAlgorithmRS512 SignAlgorithm = azkeys.SignatureAlgorithmRS512
)

// WrapKeyAlgorithm defines the key wrap algorithms supported by Azure Key Vault or Managed HSM.
type WrapKeyAlgorithm = alg.WrapKeyAlgorithm

const (
	// WrapKeyAlgorithmRSA15 uses RSA 1.5.
	WrapKeyAlgorithmRSA15 WrapKeyAlgorithm = azkeys.EncryptionAlgorithmRSA15

	// WrapKeyAlgorithmRSAOAEP uses RSA-OAEP.
	WrapKeyAlgorithmRSAOAEP WrapKeyAlgorithm = azkeys.EncryptionAlgorithmRSAOAEP

	// WrapKeyAlgorithmRSAOAEP256 uses RSA-OAEP-256.
	WrapKeyAlgorithmRSAOAEP256 WrapKeyAlgorithm = azkeys.EncryptionAlgorithmRSAOAEP256

	// WrapKeyAlgorithmA128KW uses A128-KW.
	WrapKeyAlgorithmA128KW WrapKeyAlgorithm = azkeys.EncryptionAlgorithmA128KW

	// WrapKeyAlgorithmA192KW uses A192-KW.
	WrapKeyAlgorithmA192KW WrapKeyAlgorithm = azkeys.EncryptionAlgorithmA192KW

	// WrapKeyAlgorithmA256KW uses A256-KW.
	WrapKeyAlgorithmA256KW WrapKeyAlgorithm = azkeys.EncryptionAlgorithmA256KW
)
