// Copyright 2023 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

package algorithm

import (
	"crypto"
	rng "crypto/rand"
	"crypto/rsa"
	_ "crypto/sha1"
	_ "crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/heaths/azcrypto/internal"
)

type RSA struct {
	keyID string
	key   rsa.PrivateKey
	rand  io.Reader
}

func newRSA(key azkeys.JSONWebKey, rand io.Reader) (RSA, error) {
	if *key.Kty != azkeys.KeyTypeRSA && *key.Kty != azkeys.KeyTypeRSAHSM {
		return RSA{}, fmt.Errorf("RSA does not support key type %q", *key.Kty)
	}

	if len(key.E) == 0 {
		return RSA{}, fmt.Errorf("RSA requires public exponent E")
	}

	if len(key.N) == 0 {
		return RSA{}, fmt.Errorf("RSA requires modulus N")
	}

	eb := ensureBytes(key.E, 4)
	eu := binary.BigEndian.Uint32(eb)

	_key := rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: new(big.Int).SetBytes(key.N),
			E: int(eu),
		},
	}

	if len(key.D) > 0 {
		l := len(key.N)
		_key.D = ensureBigInt(key.D, l)

		l /= 2
		_key.Primes = make([]*big.Int, 2)
		_key.Primes[0] = ensureBigInt(key.P, l)
		_key.Primes[1] = ensureBigInt(key.Q, l)

		// We could set DP, DQ, and QI but Precompute does more.
		_key.Precompute()
	}

	var keyID string
	if key.KID != nil {
		keyID = string(*key.KID)
	}

	if rand == nil {
		rand = rng.Reader
	}

	return RSA{
		keyID: keyID,
		key:   _key,
		rand:  rand,
	}, nil
}

func (r RSA) KeyType() string {
	return "RSA"
}

func (r RSA) Encrypt(algorithm EncryptAlgorithm, plaintext []byte) (EncryptResult, error) {
	var ciphertext []byte
	var err error

	getHash := func() crypto.Hash {
		switch algorithm {
		case azkeys.EncryptionAlgorithmRSAOAEP:
			return crypto.SHA1

		case azkeys.EncryptionAlgorithmRSAOAEP256:
			return crypto.SHA256

		default:
			panic("unexpected EncryptAlgorithm")
		}
	}

	switch algorithm {
	case azkeys.EncryptionAlgorithmRSAOAEP,
		azkeys.EncryptionAlgorithmRSAOAEP256:
		hash := getHash()
		ciphertext, err = rsa.EncryptOAEP(hash.New(), r.rand, &r.key.PublicKey, plaintext, nil)

	case azkeys.EncryptionAlgorithmRSA15:
		ciphertext, err = rsa.EncryptPKCS1v15(r.rand, &r.key.PublicKey, plaintext)

	default:
		return EncryptResult{}, internal.ErrUnsupported
	}

	if err != nil {
		return EncryptResult{}, err
	}

	return EncryptResult{
		Algorithm:  algorithm,
		KeyID:      r.keyID,
		Ciphertext: ciphertext,
	}, nil
}

func (r RSA) Decrypt(algorithm EncryptAlgorithm, ciphertext []byte) (DecryptResult, error) {
	var plaintext []byte
	var err error

	if !r.hasPrivateKey() {
		return DecryptResult{}, internal.ErrUnsupported
	}

	getHash := func() crypto.Hash {
		switch algorithm {
		case azkeys.EncryptionAlgorithmRSAOAEP:
			return crypto.SHA1

		case azkeys.EncryptionAlgorithmRSAOAEP256:
			return crypto.SHA256

		default:
			panic("unexpected EncryptAlgorithm")
		}
	}

	switch algorithm {
	case azkeys.EncryptionAlgorithmRSAOAEP,
		azkeys.EncryptionAlgorithmRSAOAEP256:
		hash := getHash()
		plaintext, err = rsa.DecryptOAEP(hash.New(), r.rand, &r.key, ciphertext, nil)

	case azkeys.EncryptionAlgorithmRSA15:
		plaintext, err = rsa.DecryptPKCS1v15(r.rand, &r.key, ciphertext)

	default:
		return DecryptResult{}, internal.ErrUnsupported
	}

	if err != nil {
		return DecryptResult{}, err
	}

	return DecryptResult{
		Algorithm: algorithm,
		KeyID:     r.keyID,
		Plaintext: plaintext,
	}, nil
}

func (r RSA) Sign(algorithm SignAlgorithm, digest []byte) (SignResult, error) {
	var signature []byte
	var err error

	if !r.hasPrivateKey() {
		return SignResult{}, internal.ErrUnsupported
	}

	switch algorithm {
	case azkeys.SignatureAlgorithmPS256,
		azkeys.SignatureAlgorithmPS384,
		azkeys.SignatureAlgorithmPS512:
		var hash crypto.Hash
		hash, err = GetHash(algorithm)
		if err != nil {
			return SignResult{}, err
		}
		signature, err = rsa.SignPSS(r.rand, &r.key, hash, digest, nil)

	case azkeys.SignatureAlgorithmRS256,
		azkeys.SignatureAlgorithmRS384,
		azkeys.SignatureAlgorithmRS512:
		var hash crypto.Hash
		hash, err = GetHash(algorithm)
		if err != nil {
			return SignResult{}, err
		}
		signature, err = rsa.SignPKCS1v15(r.rand, &r.key, hash, digest)

	default:
		return SignResult{}, internal.ErrUnsupported
	}

	if err != nil {
		return SignResult{}, err
	}

	return SignResult{
		Algorithm: algorithm,
		KeyID:     r.keyID,
		Signature: signature,
	}, nil
}

func (r RSA) Verify(algorithm SignAlgorithm, digest, signature []byte) (VerifyResult, error) {
	var err error
	switch algorithm {
	case azkeys.SignatureAlgorithmPS256,
		azkeys.SignatureAlgorithmPS384,
		azkeys.SignatureAlgorithmPS512:
		var hash crypto.Hash
		hash, err = GetHash(algorithm)
		if err != nil {
			return VerifyResult{}, err
		}
		err = rsa.VerifyPSS(&r.key.PublicKey, hash, digest, signature, nil)

	case azkeys.SignatureAlgorithmRS256,
		azkeys.SignatureAlgorithmRS384,
		azkeys.SignatureAlgorithmRS512:
		var hash crypto.Hash
		hash, err = GetHash(algorithm)
		if err != nil {
			return VerifyResult{}, err
		}
		err = rsa.VerifyPKCS1v15(&r.key.PublicKey, hash, digest, signature)

	default:
		return VerifyResult{}, internal.ErrUnsupported
	}

	return VerifyResult{
		Algorithm: algorithm,
		KeyID:     r.keyID,
		Valid:     err == nil,
	}, nil
}

func (r RSA) WrapKey(algorithm WrapKeyAlgorithm, key []byte) (WrapKeyResult, error) {
	var encryptedKey []byte
	var err error

	getHash := func() crypto.Hash {
		switch algorithm {
		case azkeys.EncryptionAlgorithmRSAOAEP:
			return crypto.SHA1

		case azkeys.EncryptionAlgorithmRSAOAEP256:
			return crypto.SHA256

		default:
			panic("unexpected WrapKeyAlgorithm")
		}
	}

	switch algorithm {
	case azkeys.EncryptionAlgorithmRSAOAEP,
		azkeys.EncryptionAlgorithmRSAOAEP256:
		hash := getHash()
		encryptedKey, err = rsa.EncryptOAEP(hash.New(), r.rand, &r.key.PublicKey, key, nil)

	case azkeys.EncryptionAlgorithmRSA15:
		encryptedKey, err = rsa.EncryptPKCS1v15(r.rand, &r.key.PublicKey, key)

	default:
		return WrapKeyResult{}, internal.ErrUnsupported
	}

	if err != nil {
		return WrapKeyResult{}, err
	}

	return WrapKeyResult{
		Algorithm:    algorithm,
		KeyID:        r.keyID,
		EncryptedKey: encryptedKey,
	}, nil
}

func (r RSA) UnwrapKey(algorithm WrapKeyAlgorithm, encryptedKey []byte) (UnwrapKeyResult, error) {
	var key []byte
	var err error

	if !r.hasPrivateKey() {
		return UnwrapKeyResult{}, internal.ErrUnsupported
	}

	getHash := func() crypto.Hash {
		switch algorithm {
		case azkeys.EncryptionAlgorithmRSAOAEP:
			return crypto.SHA1

		case azkeys.EncryptionAlgorithmRSAOAEP256:
			return crypto.SHA256

		default:
			panic("unexpected WrapKeyAlgorithm")
		}
	}

	switch algorithm {
	case azkeys.EncryptionAlgorithmRSAOAEP,
		azkeys.EncryptionAlgorithmRSAOAEP256:
		hash := getHash()
		key, err = rsa.DecryptOAEP(hash.New(), r.rand, &r.key, encryptedKey, nil)

	case azkeys.EncryptionAlgorithmRSA15:
		key, err = rsa.DecryptPKCS1v15(r.rand, &r.key, encryptedKey)

	default:
		return UnwrapKeyResult{}, internal.ErrUnsupported
	}

	if err != nil {
		return UnwrapKeyResult{}, err
	}

	return UnwrapKeyResult{
		Algorithm: algorithm,
		KeyID:     r.keyID,
		Key:       key,
	}, nil
}

func (r RSA) hasPrivateKey() bool {
	return r.key.D != nil
}

func ensureBigInt(src []byte, size int) *big.Int {
	b := ensureBytes(src, size)
	return new(big.Int).SetBytes(b)
}

func ensureBytes(src []byte, size int) []byte {
	l := len(src)
	if l < size {
		dst := make([]byte, size)
		copy(dst[size-l:], src)
		return dst
	}

	if l > size {
		return src[l-size:]
	}

	return src
}
