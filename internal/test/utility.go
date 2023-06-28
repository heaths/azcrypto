// Copyright 2023 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

package test

import (
	"crypto"
	"encoding/base64"
	"encoding/hex"
	"math/big"
)

// Base64ToBigInt decodes a base64 string to a big.Int.
func Base64ToBigInt(s string) *big.Int {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return new(big.Int).SetBytes(b)
}

// test.Base64ToBytes decodes a base64 string to a []byte.
func Base64ToBytes(s string) []byte {
	dst, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return dst
}

// HexToBytes decodes a hexadecimal string to a []byte.
func HexToBytes(s string) []byte {
	dst, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return dst
}

// Hash a plaintext string using SHA256.
func Hash(plaintext string, hash crypto.Hash) []byte {
	h := hash.New()
	h.Write([]byte(plaintext))
	return h.Sum(nil)
}

// Rand is a mock RNG used only for testing.
type Rand struct{}

func (r *Rand) Read(b []byte) (int, error) {
	for i := range b {
		b[i] = byte(i)
	}
	return len(b), nil
}
