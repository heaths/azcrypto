// Copyright 2023 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

package azcrypto

import (
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	alg "github.com/heaths/azcrypto/internal/algorithm"
)

// EncryptAlgorithm defines the encryption algorithms supported by Azure Key Vault or MAnaged HSM.
type EncryptAlgorithm = alg.EncryptAlgorithm

const (
	// EncryptAlgorithmRSA15 uses RSA 1.5.
	EncryptAlgorithmRSA15 EncryptAlgorithm = azkeys.JSONWebKeyEncryptionAlgorithmRSA15

	// EncryptAlgorithmRSAOAEP uses RSA-OAEP.
	EncryptAlgorithmRSAOAEP EncryptAlgorithm = azkeys.JSONWebKeyEncryptionAlgorithmRSAOAEP

	// EncryptAlgorithmRSAOAEP256 uses RSA-OAEP-256.
	EncryptAlgorithmRSAOAEP256 EncryptAlgorithm = azkeys.JSONWebKeyEncryptionAlgorithmRSAOAEP256
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
)
