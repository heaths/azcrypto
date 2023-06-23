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
	EncryptAlgorithmRSA15 EncryptAlgorithm = azkeys.JSONWebKeyEncryptionAlgorithmRSA15

	// EncryptAlgorithmRSAOAEP uses RSA-OAEP.
	EncryptAlgorithmRSAOAEP EncryptAlgorithm = azkeys.JSONWebKeyEncryptionAlgorithmRSAOAEP

	// EncryptAlgorithmRSAOAEP256 uses RSA-OAEP-256.
	EncryptAlgorithmRSAOAEP256 EncryptAlgorithm = azkeys.JSONWebKeyEncryptionAlgorithmRSAOAEP256
)

// EncryptAESCBCAlgorithm defines the encryption algorithms supported by Azure Managed HSM for encryption with AES-CBC.
//
// You should not use CBC without first ensuring the integrity of the ciphertext using an HMAC.
type EncryptAESCBCAlgorithm = alg.EncryptAESCBCAlgorithm

const (
	// EncryptAESCBCAlgorithmA128CBC uses A128-CBC with a message length appropriately padded to a multiple of 16 bytes.
	//
	// You should not use CBC without first ensuring the integrity of the ciphertext using an HMAC.
	EncryptAESCBCAlgorithmA128CBC EncryptAESCBCAlgorithm = azkeys.JSONWebKeyEncryptionAlgorithmA128CBC

	// EncryptAESCBCAlgorithmA128CBC uses A128-CBCPAD to pad a message using PKCS7 to a multiple of 16 bytes.
	//
	// You should not use CBC without first ensuring the integrity of the ciphertext using an HMAC.
	EncryptAESCBCAlgorithmA128CBCPAD EncryptAESCBCAlgorithm = azkeys.JSONWebKeyEncryptionAlgorithmA128CBCPAD

	// EncryptAESCBCAlgorithmA192CBC uses A192-CBC with a message length appropriately padded to a multiple of 16 bytes.
	//
	// You should not use CBC without first ensuring the integrity of the ciphertext using an HMAC.
	EncryptAESCBCAlgorithmA192CBC EncryptAESCBCAlgorithm = azkeys.JSONWebKeyEncryptionAlgorithmA192CBC

	// EncryptAESCBCAlgorithmA192CBC uses A192-CBCPAD to pad a message using PKCS7 to a multiple of 16 bytes.
	//
	// You should not use CBC without first ensuring the integrity of the ciphertext using an HMAC.
	EncryptAESCBCAlgorithmA192CBCPAD EncryptAESCBCAlgorithm = azkeys.JSONWebKeyEncryptionAlgorithmA192CBCPAD

	// EncryptAESCBCAlgorithmA256CBC uses A256-CBC with a message length appropriately padded to a multiple of 16 bytes.
	//
	// You should not use CBC without first ensuring the integrity of the ciphertext using an HMAC.
	EncryptAESCBCAlgorithmA256CBC EncryptAESCBCAlgorithm = azkeys.JSONWebKeyEncryptionAlgorithmA256CBC

	// EncryptAESCBCAlgorithmA256CBC uses A256-CBCPAD to pad a message using PKCS7 to a multiple of 16 bytes.
	//
	// You should not use CBC without first ensuring the integrity of the ciphertext using an HMAC.
	EncryptAESCBCAlgorithmA256CBCPAD EncryptAESCBCAlgorithm = azkeys.JSONWebKeyEncryptionAlgorithmA256CBCPAD
)

// EncryptAESGCMAlgorithm defines the encryption algorithms supported by Azure Managed HSM for encryption with AES-GCM.
type EncryptAESGCMAlgorithm = alg.EncryptAESGCMAlgorithm

const (
	// EncryptAESGCMAlgorithmA128GCM uses A128-GCM with optional authenticated data.
	EncryptAESGCMAlgorithmA128GCM EncryptAESGCMAlgorithm = azkeys.JSONWebKeyEncryptionAlgorithmA128GCM

	// EncryptAESGCMAlgorithmA192GCM uses A192-GCM with optional authenticated data.
	EncryptAESGCMAlgorithmA192GCM EncryptAESGCMAlgorithm = azkeys.JSONWebKeyEncryptionAlgorithmA192GCM

	// EncryptAESGCMAlgorithmA256GCM uses A256-GCM with optional authenticated data.
	EncryptAESGCMAlgorithmA256GCM EncryptAESGCMAlgorithm = azkeys.JSONWebKeyEncryptionAlgorithmA256GCM
)

// SignAlgorithm defines the signing algorithms supported by Azure Key Vault or Managed HSM.
type SignAlgorithm = alg.SignAlgorithm

const (
	// SignAlgorithmES256 uses the P-256 curve requiring a SHA-256 hash.
	SignAlgorithmES256 SignAlgorithm = azkeys.JSONWebKeySignatureAlgorithmES256

	// SignAlgorithmES256K uses the P-256K curve requiring a SHA-256 hash.
	SignAlgorithmES256K SignAlgorithm = azkeys.JSONWebKeySignatureAlgorithmES256K

	// SignAlgorithmES384 uses the P-384 curve requiring a SHA-384 hash.
	SignAlgorithmES384 SignAlgorithm = azkeys.JSONWebKeySignatureAlgorithmES384

	// SignAlgorithmES512 uses the P-521 curve requiring a SHA-512 hash.
	SignAlgorithmES512 SignAlgorithm = azkeys.JSONWebKeySignatureAlgorithmES512

	// SignAlgorithmPS256 uses RSASSA-PSS using a SHA-256 hash.
	SignAlgorithmPS256 SignAlgorithm = azkeys.JSONWebKeySignatureAlgorithmPS256

	// SignAlgorithmPS384 uses RSASSA-PSS using a SHA-384 hash.
	SignAlgorithmPS384 SignAlgorithm = azkeys.JSONWebKeySignatureAlgorithmPS384

	// SignAlgorithmPS512 uses RSASSA-PSS using a SHA-512 hash.
	SignAlgorithmPS512 SignAlgorithm = azkeys.JSONWebKeySignatureAlgorithmPS512

	// SignAlgorithmRS256 uses RSASSA-PKCS1-v1_5 using a SHA256 hash.
	SignAlgorithmRS256 SignAlgorithm = azkeys.JSONWebKeySignatureAlgorithmRS256

	// SignAlgorithmRS384 uses RSASSA-PKCS1-v1_5 using a SHA384 hash.
	SignAlgorithmRS384 SignAlgorithm = azkeys.JSONWebKeySignatureAlgorithmRS384

	// SignAlgorithmRS512 uses RSASSA-PKCS1-v1_5 using a SHA512 hash.
	SignAlgorithmRS512 SignAlgorithm = azkeys.JSONWebKeySignatureAlgorithmRS512
)

// WrapKeyAlgorithm defines the key wrap algorithms supported by Azure Key Vault or Managed HSM.
type WrapKeyAlgorithm = alg.WrapKeyAlgorithm

const (
	// WrapKeyAlgorithmRSA15 uses RSA 1.5.
	WrapKeyAlgorithmRSA15 WrapKeyAlgorithm = azkeys.JSONWebKeyEncryptionAlgorithmRSA15

	// WrapKeyAlgorithmRSAOAEP uses RSA-OAEP.
	WrapKeyAlgorithmRSAOAEP WrapKeyAlgorithm = azkeys.JSONWebKeyEncryptionAlgorithmRSAOAEP

	// WrapKeyAlgorithmRSAOAEP256 uses RSA-OAEP-256.
	WrapKeyAlgorithmRSAOAEP256 WrapKeyAlgorithm = azkeys.JSONWebKeyEncryptionAlgorithmRSAOAEP256

	// WrapKeyAlgorithmA128KW uses A128-KW.
	WrapKeyAlgorithmA128KW WrapKeyAlgorithm = azkeys.JSONWebKeyEncryptionAlgorithmA128KW

	// WrapKeyAlgorithmA192KW uses A192-KW.
	WrapKeyAlgorithmA192KW WrapKeyAlgorithm = azkeys.JSONWebKeyEncryptionAlgorithmA192KW

	// WrapKeyAlgorithmA256KW uses A256-KW.
	WrapKeyAlgorithmA256KW WrapKeyAlgorithm = azkeys.JSONWebKeyEncryptionAlgorithmA256KW
)
