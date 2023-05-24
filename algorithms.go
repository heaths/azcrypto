// Copyright 2023 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

package azcrypto

import (
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	alg "github.com/heaths/azcrypto/internal/algorithm"
)

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
