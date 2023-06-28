// Copyright 2023 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

package algorithm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	rng "crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/heaths/azcrypto/internal"
)

type ECDsa struct {
	keyID string
	key   ecdsa.PrivateKey
	rand  io.Reader
}

func newECDsa(key azkeys.JSONWebKey, rand io.Reader) (ECDsa, error) {
	if *key.Kty != azkeys.KeyTypeEC && *key.Kty != azkeys.KeyTypeECHSM {
		return ECDsa{}, fmt.Errorf("ECDsa does not support key type %q", *key.Kty)
	}

	if key.Crv == nil {
		return ECDsa{}, errors.New("ECDsa requires curve name")
	}
	curve, err := fromCurve(*key.Crv)
	if err != nil {
		return ECDsa{}, err
	}

	if len(key.X) == 0 || len(key.Y) == 0 {
		return ECDsa{}, errors.New("ECDsa requires public key coordinates X, Y")
	}

	_key := ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
			X:     new(big.Int).SetBytes(key.X),
			Y:     new(big.Int).SetBytes(key.Y),
		},
	}

	if len(key.D) != 0 {
		_key.D = new(big.Int).SetBytes(key.D)
	}

	var keyID string
	if key.KID != nil {
		keyID = string(*key.KID)
	}

	if rand == nil {
		rand = rng.Reader
	}

	return ECDsa{
		keyID: keyID,
		key:   _key,
		rand:  rand,
	}, nil
}

func fromCurve(crv azkeys.CurveName) (elliptic.Curve, error) {
	switch crv {
	case azkeys.CurveNameP256:
		return elliptic.P256(), nil
	case azkeys.CurveNameP384:
		return elliptic.P384(), nil
	case azkeys.CurveNameP521:
		return elliptic.P521(), nil
	default:
		return nil, internal.ErrUnsupported
	}
}

func (c ECDsa) Sign(algorithm SignAlgorithm, digest []byte) (SignResult, error) {
	if !supportsAlgorithm(
		algorithm,
		azkeys.SignatureAlgorithmES256,
		azkeys.SignatureAlgorithmES384,
		azkeys.SignatureAlgorithmES512,
	) {
		return SignResult{}, internal.ErrUnsupported
	}

	if !c.hasPrivateKey() {
		return SignResult{}, internal.ErrUnsupported
	}

	r, s, err := ecdsa.Sign(c.rand, &c.key, digest)
	if err != nil {
		return SignResult{}, err
	}

	rBytes := r.Bytes()
	sBytes := s.Bytes()
	signature := make([]byte, len(rBytes)+len(sBytes))
	copy(signature, rBytes)
	copy(signature[len(rBytes):], sBytes)

	return SignResult{
		Algorithm: algorithm,
		KeyID:     c.keyID,
		Signature: signature,
	}, nil
}

func (c ECDsa) Verify(algorithm SignAlgorithm, digest, signature []byte) (VerifyResult, error) {
	if !supportsAlgorithm(
		algorithm,
		azkeys.SignatureAlgorithmES256,
		azkeys.SignatureAlgorithmES384,
		azkeys.SignatureAlgorithmES512,
	) {
		return VerifyResult{}, internal.ErrUnsupported
	}

	// Key Vault and Managed HSM concatenate r and s components.
	r := new(big.Int).SetBytes(signature[:len(signature)/2])
	s := new(big.Int).SetBytes(signature[len(signature)/2:])

	return VerifyResult{
		Algorithm: algorithm,
		KeyID:     c.keyID,
		Valid:     ecdsa.Verify(&c.key.PublicKey, digest, r, s),
	}, nil
}

func (c ECDsa) hasPrivateKey() bool {
	return c.key.D != nil
}
