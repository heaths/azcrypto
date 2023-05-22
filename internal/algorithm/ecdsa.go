// Copyright 2023 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

package algorithm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"
	"log"
	"math/big"

	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azkeys"
	"github.com/heaths/azcrypto/internal"
)

type ECDsa struct {
	keyID string
	pub   ecdsa.PublicKey
}

func newECDsa(key azkeys.JSONWebKey) (ECDsa, error) {
	if *key.Kty != azkeys.JSONWebKeyTypeEC && *key.Kty != azkeys.JSONWebKeyTypeECHSM {
		return ECDsa{}, fmt.Errorf("ECDsa does not support key type %q", *key.Kty)
	}

	if key.Crv == nil {
		return ECDsa{}, errors.New("ECDsa requires curve name")
	}

	curve, err := fromCurve(*key.Crv)
	if err != nil {
		return ECDsa{}, err
	}

	var keyID string
	if key.KID != nil {
		keyID = string(*key.KID)
	}

	return ECDsa{
		keyID: keyID,
		pub: ecdsa.PublicKey{
			Curve: curve,
			X:     new(big.Int).SetBytes(key.X),
			Y:     new(big.Int).SetBytes(key.Y),
		},
	}, nil
}

func fromCurve(crv azkeys.JSONWebKeyCurveName) (elliptic.Curve, error) {
	switch crv {
	case azkeys.JSONWebKeyCurveNameP256:
		return elliptic.P256(), nil
	case azkeys.JSONWebKeyCurveNameP384:
		return elliptic.P384(), nil
	case azkeys.JSONWebKeyCurveNameP521:
		return elliptic.P521(), nil
	default:
		return nil, internal.ErrUnsupported
	}
}

func (c ECDsa) Sign(algorithm SignatureAlgorithm, digest []byte) (SignResult, error) {
	return SignResult{}, internal.ErrUnsupported
}

func (c ECDsa) Verify(algorithm SignatureAlgorithm, digest, signature []byte) (VerifyResult, error) {
	log.Println("Verifying locally")

	// Naive split of r, s.
	// See https://github.com/schaabs/azure-keyvault-java/blob/e643aff088bb5cc60bef23ba4edb67b518301fa8/azure-keyvault-cryptography/src/main/java/com/microsoft/azure/keyvault/cryptography/SignatureEncoding.java#L130
	r := new(big.Int).SetBytes(signature[:len(signature)/2])
	s := new(big.Int).SetBytes(signature[len(signature)/2:])

	return VerifyResult{
		Algorithm: algorithm,
		KeyID:     c.keyID,
		Valid:     ecdsa.Verify(&c.pub, digest, r, s),
	}, nil
}
