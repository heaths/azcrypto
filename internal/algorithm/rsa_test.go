// Copyright 2023 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

// cspell:disable

package algorithm

import (
	"crypto"
	"crypto/rsa"
	"math/big"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/heaths/azcrypto/internal"
	"github.com/heaths/azcrypto/internal/test"
	"github.com/stretchr/testify/require"
)

func TestNewRSA(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		key    azkeys.JSONWebKey
		keyID  string
		errMsg string
	}{
		{
			name: "unsupported kty",
			key: azkeys.JSONWebKey{
				Kty: to.Ptr(azkeys.KeyTypeEC),
			},
			errMsg: `RSA does not support key type "EC"`,
		},
		{
			name: "missing E",
			key: azkeys.JSONWebKey{
				Kty: to.Ptr(azkeys.KeyTypeRSA),
				N:   testRSA.key.N.Bytes(),
			},
			errMsg: "RSA requires public exponent E",
		},
		{
			name: "missing N",
			key: azkeys.JSONWebKey{
				Kty: to.Ptr(azkeys.KeyTypeRSA),
				E:   test.Base64ToBytes("AQAB"),
			},
			errMsg: "RSA requires modulus N",
		},
		{
			name: "with keyID",
			key: azkeys.JSONWebKey{
				Kty: to.Ptr(azkeys.KeyTypeRSA),
				KID: to.Ptr(azkeys.ID("kid")),
				E:   test.Base64ToBytes("AQAB"),
				N:   testRSA.key.N.Bytes(),
			},
			keyID: "kid",
		},
		{
			name: "with private key",
			key: azkeys.JSONWebKey{
				Kty: to.Ptr(azkeys.KeyTypeRSA),
				E:   test.Base64ToBytes("AQAB"),
				N:   testRSA.key.N.Bytes(),
				D:   testRSA.key.D.Bytes(),
				P:   testRSA.key.Primes[0].Bytes(),
				Q:   testRSA.key.Primes[1].Bytes(),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			alg, err := newRSA(tt.key, nil)
			if tt.errMsg != "" {
				require.EqualError(t, err, tt.errMsg)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.keyID, alg.keyID)
			require.NotNil(t, alg.rand)

			var encrypter Encrypter
			require.Implements(t, &encrypter, alg)

			var wrapper KeyWrapper
			require.Implements(t, &wrapper, alg)
		})
	}
}

func TestEnsureBytes(t *testing.T) {
	t.Parallel()

	sut := func(src []byte) []byte {
		return ensureBytes(src, 4)
	}

	require.Equal(t, []byte{0x00, 0x00, 0x00, 0x00}, sut([]byte{}))
	require.Equal(t, []byte{0x00, 0x00, 0x00, 0x01}, sut([]byte{0x01}))
	require.Equal(t, []byte{0x00, 0x00, 0x02, 0x01}, sut([]byte{0x02, 0x01}))
	require.Equal(t, []byte{0x00, 0x03, 0x02, 0x01}, sut([]byte{0x03, 0x02, 0x01}))
	require.Equal(t, []byte{0x04, 0x03, 0x02, 0x01}, sut([]byte{0x04, 0x03, 0x02, 0x01}))
	require.Equal(t, []byte{0x04, 0x03, 0x02, 0x01}, sut([]byte{0x05, 0x04, 0x03, 0x02, 0x01}))
}

func TestRSA_Encrypt(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		alg        EncryptAlgorithm
		ciphertext string
		err        error
	}{
		{
			name:       "RSA1_5",
			alg:        azkeys.EncryptionAlgorithmRSA15,
			ciphertext: "nYEVBOXn9BxPUCfyo0BcScrlgosCElPqOto8/KLN8wIPrxcOxSyVeZ0bg5Z5kcg8mhkwqhvWAHJ+yUa1QziLI4OdNninkG2kz3p3nBHF1vpwbwGNdEuB0XK8w1ohU0XFrZ8e3un9TdcyXswvaKI9CnJMaC9aul2Oqt8yax/38OBGyCzHIugI6+anNEus81p22y6TEDc5zBdeHA8O+xbJ1MLiiLZzcdOLCN/80tRZnSkBjnVi6mm9198DqTGshJbc7cXhh7Ha5GTM/Bo8XHzmLDL4B2IzKu/KKXQIATiK0exGFF3lAQAWom/k2gFDA/czpYVBocuCPgKXvv0eJEKgEw==",
		},
		{
			name:       "RSA-OAEP",
			alg:        azkeys.EncryptionAlgorithmRSAOAEP,
			ciphertext: "WM/wJfgJsIYsL2FqQLL0sXf8ACiEt48qCjjJxsl4od3Rnw4HWHARF+3EzJ++rByOrUHTgGPgj351A9OHGiozMawYoG3m62NsppsgX9fKtlkUtctWI+UMvBv0vLJTlLNX9H3qpQdoKYDMja4tphinYJ+1rpo1Z3/TONfk/k8DOQJOPs9OA3vGBJNIhVqczSOmPZaSAn++rYe7Re7C0JCOG9XXuD5Bbre2GSPwaD2q2db817LuQjQTqdzDqN1VeSMlosR7u5+42WlM69znjA6tk2EevF4LOuxaSiyQGaaFlkxUQciQRmRkoNYATb9pXXeDlDSCtRtBRY0Zo8jWQG/3rA==",
		},
		{
			name:       "RSA-OAEP-256",
			alg:        azkeys.EncryptionAlgorithmRSAOAEP256,
			ciphertext: "bcHiz+zwxFCsfv6P8T/kq+3dzkndX6e5ImCBZRHYObXjr6WrmUqoe5ASgxeT/sJtp7W0uSqe2buQO2EOYzyzVuuArCt3JOEiILJCsns2vnukTm9F0x3FpgVW0DysnXcCvYE9MLVvcwVgn5g8tOsQArPexGt4Wr7kLR0nHnBlwqTrlrj5gJvxQYP5xGOIsFcJz9bnsB3MZT1dQS8y6HTGHiEPQsTnh7/RTwPsXsQkRBxGKcAzYDN5IdhrpbxtDs7DlBLUcvcE+6F+lNxxl1x/3zDUY922STb8GFZwbikvL27WrhhF5zE1LEokrm2GBWMx3I6ovRWUED+9vepdLV+W+A==",
		},
		{
			name: "unsupported",
			alg:  azkeys.EncryptionAlgorithmA128CBC,
			err:  internal.ErrUnsupported,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expected := test.Base64ToBytes(tt.ciphertext)
			result, err := testRSA.Encrypt(tt.alg, []byte("plaintext"))
			if tt.err != nil {
				require.ErrorIs(t, err, tt.err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, expected, result.Ciphertext)
		})
	}
}

func TestRSA_Decrypt(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		key        *RSA
		alg        EncryptAlgorithm
		ciphertext string
		err        error
	}{
		{
			name:       "RSA1_5",
			alg:        azkeys.EncryptionAlgorithmRSA15,
			ciphertext: "nYEVBOXn9BxPUCfyo0BcScrlgosCElPqOto8/KLN8wIPrxcOxSyVeZ0bg5Z5kcg8mhkwqhvWAHJ+yUa1QziLI4OdNninkG2kz3p3nBHF1vpwbwGNdEuB0XK8w1ohU0XFrZ8e3un9TdcyXswvaKI9CnJMaC9aul2Oqt8yax/38OBGyCzHIugI6+anNEus81p22y6TEDc5zBdeHA8O+xbJ1MLiiLZzcdOLCN/80tRZnSkBjnVi6mm9198DqTGshJbc7cXhh7Ha5GTM/Bo8XHzmLDL4B2IzKu/KKXQIATiK0exGFF3lAQAWom/k2gFDA/czpYVBocuCPgKXvv0eJEKgEw==",
		},
		{
			name:       "RSA-OAEP",
			alg:        azkeys.EncryptionAlgorithmRSAOAEP,
			ciphertext: "WM/wJfgJsIYsL2FqQLL0sXf8ACiEt48qCjjJxsl4od3Rnw4HWHARF+3EzJ++rByOrUHTgGPgj351A9OHGiozMawYoG3m62NsppsgX9fKtlkUtctWI+UMvBv0vLJTlLNX9H3qpQdoKYDMja4tphinYJ+1rpo1Z3/TONfk/k8DOQJOPs9OA3vGBJNIhVqczSOmPZaSAn++rYe7Re7C0JCOG9XXuD5Bbre2GSPwaD2q2db817LuQjQTqdzDqN1VeSMlosR7u5+42WlM69znjA6tk2EevF4LOuxaSiyQGaaFlkxUQciQRmRkoNYATb9pXXeDlDSCtRtBRY0Zo8jWQG/3rA==",
		},
		{
			name:       "RSA-OAEP-256",
			alg:        azkeys.EncryptionAlgorithmRSAOAEP256,
			ciphertext: "bcHiz+zwxFCsfv6P8T/kq+3dzkndX6e5ImCBZRHYObXjr6WrmUqoe5ASgxeT/sJtp7W0uSqe2buQO2EOYzyzVuuArCt3JOEiILJCsns2vnukTm9F0x3FpgVW0DysnXcCvYE9MLVvcwVgn5g8tOsQArPexGt4Wr7kLR0nHnBlwqTrlrj5gJvxQYP5xGOIsFcJz9bnsB3MZT1dQS8y6HTGHiEPQsTnh7/RTwPsXsQkRBxGKcAzYDN5IdhrpbxtDs7DlBLUcvcE+6F+lNxxl1x/3zDUY922STb8GFZwbikvL27WrhhF5zE1LEokrm2GBWMx3I6ovRWUED+9vepdLV+W+A==",
		},
		{
			name: "missing private key",
			key: &RSA{
				key: rsa.PrivateKey{
					PublicKey: testRSA.key.PublicKey,
				},
				rand: testRSA.rand,
			},
			alg: azkeys.EncryptionAlgorithmRSAOAEP,
			err: internal.ErrUnsupported,
		},
		{
			name: "unsupported",
			alg:  azkeys.EncryptionAlgorithmA128CBC,
			err:  internal.ErrUnsupported,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ciphertext := test.Base64ToBytes(tt.ciphertext)
			rsa := tt.key
			if rsa == nil {
				rsa = &testRSA
			}

			result, err := rsa.Decrypt(tt.alg, ciphertext)
			if tt.err != nil {
				require.ErrorIs(t, err, tt.err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, []byte("plaintext"), result.Plaintext)
		})
	}
}

func TestRSA_Sign(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		key       *RSA
		alg       SignAlgorithm
		hash      crypto.Hash
		signature string
		err       error
	}{
		{
			name:      "PS256",
			alg:       azkeys.SignatureAlgorithmPS256,
			hash:      crypto.SHA256,
			signature: "REvKoEEJvZBaEAAbtJxTPr+jLyLX0ijgxLq34j4y5Qi/B5XsKaQ3zQl/Q6jdEOXegZnNYSsevgEmV9mvpXAxz8mWUA8ljkP3lUU7ItUF/nPL7OCVkQv7AgbgfLILiJroyJBFACHN48bPMN7SzVA4PU5yFZ/3t/QMCE3ZDpjkFUHHJA4SwZyqpPaIGucmcBKyvIVP+k+u5istkUwHAPuYeZ/UF1+6GHdUVGtu4/m6xLOws12dTYVmB/ynnfpdGneF+UMdQxwtWkU0Z8rUtnTwZPINyqkIS78FyifFVgQElIbIJm4bcROWQgxjwLWv8AAGEbutSS9yqxM24hFs8MOXfQ==",
		},
		{
			name:      "RS256",
			alg:       azkeys.SignatureAlgorithmRS256,
			hash:      crypto.SHA256,
			signature: "dFJj9RoYtdamUS1ltFAd5uqsQCv3rjXUH4Dw9O+mdKYTyu4jnYJvHkOBYn8JVhJpDmbEcLpliolgqyLrgb21HOTm6vpPqtRZUzUfK9m1sXls5yfHrKM2E7jmEe5MJf1+/v22KdpHrJOG4qOZI9xZET0o/+XSpzImHNm6E5PpIUOGssj/GPprujuezn66OIVJ7mys6BXXrK8u3i7Mhgt/F562BvT8/TZc3j/kh9Allgi3eH3MFbe4ZVRRbJlSorRiMwnPTIlu4ZgdzpebxYej4LS/JpW1jNCR0b52UtWybACxRCo7dd9btmIHrxQlMVOmP4Wm663ahqXHRKTpHfrAHA==",
		},
		{
			name:      "PS384",
			alg:       azkeys.SignatureAlgorithmPS384,
			hash:      crypto.SHA384,
			signature: "GUNCfsYVHi7yYHBeEwBtajlr/eqKLh+Skh66uSkDZgTMEb+736VRFDuHTw/TpzIAwMIZDayLo67po1eQEzU0nbI6xxUEQHXdy19ne0C5P7v/xJ8A/Tkqbt4ffv9Pl1hKmuyE1fnogMH4v8XNN+RaaebG7AFlvThEiMnuFp3tVsQi8pk0tbtr1v2JHC6Imm8e4DnLxybRbCwoQkzyPZ2dC/EZBAio9FO66Eh0jBHYNNmkut3JVnToujIx+pr+uOKfOxcNjJlJZWbUeus8aqF7wnLtiRjqJdjBpEC42XYj6xITl+vG9eVkvjdnK2ZbnfxkAfOwv46GYY2L8LUnpKCy3Q==",
		},
		{
			name:      "RS384",
			alg:       azkeys.SignatureAlgorithmRS384,
			hash:      crypto.SHA384,
			signature: "DquJYW52dTjEDfsDLaJwjEQb1b2Vb8dulhfNhLlEh+CinZWd6BxWaXUkzNSF8YbncdFTMYu/05scDrmFXzD1G/8PdXnVjIGWfNSwyuPyw9dOAqp1NLOdFQZl9qWqCz4rIdep6hrKdF67CtFEWba5HqLQy7tFAvV7yTFzuUvGI3+2GPfBrivmDibpTIAqbB2mn1pdjAkyPHN6YSjD9JlULalBqiNetbZU9OBCwNZFDcmHKALs2UsIIjMyKgdYJ/EXugLQR86uGa3DNmDNsAxgIwxDUmv2R5zqvHy5rYEzArU/ooc8GNATE9n7KXvS+0aMwd7rncbC8gu6Nkgfq4WUog==",
		},
		{
			name:      "PS512",
			alg:       azkeys.SignatureAlgorithmPS512,
			hash:      crypto.SHA512,
			signature: "uZQxkkAP8VpGXJeMVkCrfuEJ+2WHUvziNJq+DvoKxkZzJfC6rQNKBVMoMPjCAzU8T1Mli56GIH7WPjQzqX8Obxojk3A7Y4J+HweGQZDQGwrAv0zqPPUR3jl+P35xYOrZN4Wn6wEB88sDkelTDLfhwVrBa50Bg0+KkhkmzsC7Wauy6cpZc6oBcLG77WHunUOUnO7XtTXbAkIJ3rRTFDVBeuEG4cosRtQ82qbAldOd/u6OEdiG6j06O/zvW4Gl5bN9DuLke/GEXpfXRbX4oRPllkSPx+Eqxo3izn5wLUN5n1DJxe0If9c9V6YbH64vLmjlKxNrWp+N8/aAJNBVs9m+fA==",
		},
		{
			name:      "RS512",
			alg:       azkeys.SignatureAlgorithmRS512,
			hash:      crypto.SHA512,
			signature: "YOWlOknuzqU+6RYqADFJC528uijy72Bk/oY0tzKkk89QhbpDmsFRFUYBJPnCTMZHKxIOtoYvu5CaQORNL+qTYgBTXCPBTMXPElTtNxyUYKPlrFeIs2gO94ZWbI/fNbHYr+ugxqXNS2ccbMn38UYzrx/DiH6hPXwBDmVdM4a2c1/nONg3CHipRJwCdiYyRSrVt1ucAfzQJJ++POmayDmxLTuERTQLZy5nTj1TsJx+NL2o0Co7Nc7Si3kvS77Oc56DBnjGU2AVqIMjxWKloaNh7i9GrZklCeUyCJ/Aj6OcW/MKli7BSdH+bF1UEql0fWdvHfL78OfdZYJr+hLIUZ7Gag==",
		},
		{
			name: "missing private key",
			key: &RSA{
				key: rsa.PrivateKey{
					PublicKey: testRSA.key.PublicKey,
				},
			},
			alg:  azkeys.SignatureAlgorithmPS256,
			hash: crypto.SHA256,
			err:  internal.ErrUnsupported,
		},
		{
			name: "unsupported",
			alg:  azkeys.SignatureAlgorithmES256,
			hash: crypto.SHA256,
			err:  internal.ErrUnsupported,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expected := test.Base64ToBytes(tt.signature)
			rsa := tt.key
			if rsa == nil {
				rsa = &testRSA
			}

			result, err := rsa.Sign(tt.alg, test.Hash("message", tt.hash))
			if tt.err != nil {
				require.ErrorIs(t, err, tt.err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.alg, result.Algorithm)
			require.Equal(t, expected, result.Signature)
		})
	}
}

func TestRSA_Verify(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		alg       SignAlgorithm
		hash      crypto.Hash
		signature string
		err       error
	}{
		{
			name:      "PS256",
			alg:       azkeys.SignatureAlgorithmPS256,
			hash:      crypto.SHA256,
			signature: "REvKoEEJvZBaEAAbtJxTPr+jLyLX0ijgxLq34j4y5Qi/B5XsKaQ3zQl/Q6jdEOXegZnNYSsevgEmV9mvpXAxz8mWUA8ljkP3lUU7ItUF/nPL7OCVkQv7AgbgfLILiJroyJBFACHN48bPMN7SzVA4PU5yFZ/3t/QMCE3ZDpjkFUHHJA4SwZyqpPaIGucmcBKyvIVP+k+u5istkUwHAPuYeZ/UF1+6GHdUVGtu4/m6xLOws12dTYVmB/ynnfpdGneF+UMdQxwtWkU0Z8rUtnTwZPINyqkIS78FyifFVgQElIbIJm4bcROWQgxjwLWv8AAGEbutSS9yqxM24hFs8MOXfQ==",
		},
		{
			name:      "RS256",
			alg:       azkeys.SignatureAlgorithmRS256,
			hash:      crypto.SHA256,
			signature: "dFJj9RoYtdamUS1ltFAd5uqsQCv3rjXUH4Dw9O+mdKYTyu4jnYJvHkOBYn8JVhJpDmbEcLpliolgqyLrgb21HOTm6vpPqtRZUzUfK9m1sXls5yfHrKM2E7jmEe5MJf1+/v22KdpHrJOG4qOZI9xZET0o/+XSpzImHNm6E5PpIUOGssj/GPprujuezn66OIVJ7mys6BXXrK8u3i7Mhgt/F562BvT8/TZc3j/kh9Allgi3eH3MFbe4ZVRRbJlSorRiMwnPTIlu4ZgdzpebxYej4LS/JpW1jNCR0b52UtWybACxRCo7dd9btmIHrxQlMVOmP4Wm663ahqXHRKTpHfrAHA==",
		},
		{
			name:      "PS384",
			alg:       azkeys.SignatureAlgorithmPS384,
			hash:      crypto.SHA384,
			signature: "GUNCfsYVHi7yYHBeEwBtajlr/eqKLh+Skh66uSkDZgTMEb+736VRFDuHTw/TpzIAwMIZDayLo67po1eQEzU0nbI6xxUEQHXdy19ne0C5P7v/xJ8A/Tkqbt4ffv9Pl1hKmuyE1fnogMH4v8XNN+RaaebG7AFlvThEiMnuFp3tVsQi8pk0tbtr1v2JHC6Imm8e4DnLxybRbCwoQkzyPZ2dC/EZBAio9FO66Eh0jBHYNNmkut3JVnToujIx+pr+uOKfOxcNjJlJZWbUeus8aqF7wnLtiRjqJdjBpEC42XYj6xITl+vG9eVkvjdnK2ZbnfxkAfOwv46GYY2L8LUnpKCy3Q==",
		},
		{
			name:      "RS384",
			alg:       azkeys.SignatureAlgorithmRS384,
			hash:      crypto.SHA384,
			signature: "DquJYW52dTjEDfsDLaJwjEQb1b2Vb8dulhfNhLlEh+CinZWd6BxWaXUkzNSF8YbncdFTMYu/05scDrmFXzD1G/8PdXnVjIGWfNSwyuPyw9dOAqp1NLOdFQZl9qWqCz4rIdep6hrKdF67CtFEWba5HqLQy7tFAvV7yTFzuUvGI3+2GPfBrivmDibpTIAqbB2mn1pdjAkyPHN6YSjD9JlULalBqiNetbZU9OBCwNZFDcmHKALs2UsIIjMyKgdYJ/EXugLQR86uGa3DNmDNsAxgIwxDUmv2R5zqvHy5rYEzArU/ooc8GNATE9n7KXvS+0aMwd7rncbC8gu6Nkgfq4WUog==",
		},
		{
			name:      "PS512",
			alg:       azkeys.SignatureAlgorithmPS512,
			hash:      crypto.SHA512,
			signature: "uZQxkkAP8VpGXJeMVkCrfuEJ+2WHUvziNJq+DvoKxkZzJfC6rQNKBVMoMPjCAzU8T1Mli56GIH7WPjQzqX8Obxojk3A7Y4J+HweGQZDQGwrAv0zqPPUR3jl+P35xYOrZN4Wn6wEB88sDkelTDLfhwVrBa50Bg0+KkhkmzsC7Wauy6cpZc6oBcLG77WHunUOUnO7XtTXbAkIJ3rRTFDVBeuEG4cosRtQ82qbAldOd/u6OEdiG6j06O/zvW4Gl5bN9DuLke/GEXpfXRbX4oRPllkSPx+Eqxo3izn5wLUN5n1DJxe0If9c9V6YbH64vLmjlKxNrWp+N8/aAJNBVs9m+fA==",
		},
		{
			name:      "RS512",
			alg:       azkeys.SignatureAlgorithmRS512,
			hash:      crypto.SHA512,
			signature: "YOWlOknuzqU+6RYqADFJC528uijy72Bk/oY0tzKkk89QhbpDmsFRFUYBJPnCTMZHKxIOtoYvu5CaQORNL+qTYgBTXCPBTMXPElTtNxyUYKPlrFeIs2gO94ZWbI/fNbHYr+ugxqXNS2ccbMn38UYzrx/DiH6hPXwBDmVdM4a2c1/nONg3CHipRJwCdiYyRSrVt1ucAfzQJJ++POmayDmxLTuERTQLZy5nTj1TsJx+NL2o0Co7Nc7Si3kvS77Oc56DBnjGU2AVqIMjxWKloaNh7i9GrZklCeUyCJ/Aj6OcW/MKli7BSdH+bF1UEql0fWdvHfL78OfdZYJr+hLIUZ7Gag==",
		},
		{
			name: "unsupported",
			alg:  azkeys.SignatureAlgorithmES256,
			hash: crypto.SHA256,
			err:  internal.ErrUnsupported,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signature := test.Base64ToBytes(tt.signature)
			result, err := testRSA.Verify(tt.alg, test.Hash("message", tt.hash), signature)
			if tt.err != nil {
				require.ErrorIs(t, err, tt.err)
				return
			}
			require.NoError(t, err)
			require.True(t, result.Valid)
		})
	}
}

func TestRSA_WrapKey(t *testing.T) {
	t.Parallel()

	key := test.Base64ToBytes("bW9jayBhZXMtMTI4IGtleQ==")
	tests := []struct {
		name      string
		alg       WrapKeyAlgorithm
		encrypted string
		err       error
	}{
		{
			name:      "RSA1_5",
			alg:       azkeys.EncryptionAlgorithmRSA15,
			encrypted: "odbQwAO0wBAg4We9KGljC3iUD3dbEULjEd0mTvMHv9CVDTZCe0OU39GmXiBY7y3wmv+sW9A5ULRAmY8uwFsT1FUQza+8udiXoeG/gr93tYYITW9XNktKT7FXscv3g4hFEetpJAeF0MG+etGtqBRUi58mK/R4qcNvDp3jR3WFlL0L3ipI05oOm4GP0wGcUogvYkQOhMVx8ap8Cvw0j6ryLzWX863LiBNb+IVxRIjl5bl4dRTDRXkD3x4IWaOefX8dfXUCQJN4WCAd2ldkAlITyjdklpwhuF0eQC24bIrej8s/Uet8NPnm8yN/yhiidlKj1Q1yxpcV7rqSxQrftdp5Bg==",
		},
		{
			name:      "RSA-OAEP",
			alg:       azkeys.EncryptionAlgorithmRSAOAEP,
			encrypted: "v3GX60vQLrsjW8tKEKT7Se6GwaJwZPxt7JT64xchvCIz7Bin+ehqv6IOxNZbQPSgMmLdxIL4VXjs5Yexeh/LWmGM25hrHoEsVyqVT4X2UD71USSrr/ftrEV/7exKy4xwqVv1Dyjvuw36nONGlkoYdZY9ZMwZgBZL0ZmaN5OoiWEmy1r8fJD1eQXR8tHgc0z7qxDrneZyRcqCAa8AMJFjzJ+aRrTnny5hqQ3/vSNZUXI+Bwv6mhw3UcKjFuUYV3kC8+h3FfK6+rbZOigr7V5uzBm0sj0yGw/UJI/pgio/U1l6kRXBUSefBHA3y59arZsvkjuWG9L8h1RZgR5bfWzkPg==",
		},
		{
			name:      "RSA-OAEP-256",
			alg:       azkeys.EncryptionAlgorithmRSAOAEP256,
			encrypted: "S4pzhGlZsdNskUwheWQSxaAR7ELBNimilET33Zz1261q9TFXo3XiTsFmOfVA1+xlzC59T3T1t7d+x4c8bEBEACY/x5YKxB/a64hxLc3SUdx+MxhNrZgiuRFK28s0zD3ReKrGuPcUPJhn6SROSmO2AQ2J5EHKCVgOmct1huxZMpRPlxJuFZ3bLk4eKuixoHt1hXPmA1oHeVagDhlm1+dbAFDhYbLkZnEl19/uNgO+oqOxR54lJqWQNPNSY4hRn7WGv60eIqMHZ44dtjBAwNWQA833zRCI8ihPSnz4miULlWS9BEfk2khKsqkVYotFNEjKIzp5fJNFIuxFnu8M1eGp8Q==",
		},
		{
			name: "unsupported",
			alg:  azkeys.EncryptionAlgorithmA128CBC,
			err:  internal.ErrUnsupported,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expected := test.Base64ToBytes(tt.encrypted)
			result, err := testRSA.WrapKey(tt.alg, key)
			if err != nil {
				require.ErrorIs(t, err, tt.err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, expected, result.EncryptedKey)
		})
	}
}

func TestRSA_UnwrapKey(t *testing.T) {
	t.Parallel()

	key := test.Base64ToBytes("bW9jayBhZXMtMTI4IGtleQ==")
	tests := []struct {
		name      string
		key       *RSA
		alg       WrapKeyAlgorithm
		encrypted string
		err       error
	}{
		{
			name:      "RSA1_5",
			alg:       azkeys.EncryptionAlgorithmRSA15,
			encrypted: "odbQwAO0wBAg4We9KGljC3iUD3dbEULjEd0mTvMHv9CVDTZCe0OU39GmXiBY7y3wmv+sW9A5ULRAmY8uwFsT1FUQza+8udiXoeG/gr93tYYITW9XNktKT7FXscv3g4hFEetpJAeF0MG+etGtqBRUi58mK/R4qcNvDp3jR3WFlL0L3ipI05oOm4GP0wGcUogvYkQOhMVx8ap8Cvw0j6ryLzWX863LiBNb+IVxRIjl5bl4dRTDRXkD3x4IWaOefX8dfXUCQJN4WCAd2ldkAlITyjdklpwhuF0eQC24bIrej8s/Uet8NPnm8yN/yhiidlKj1Q1yxpcV7rqSxQrftdp5Bg==",
		},
		{
			name:      "RSA-OAEP",
			alg:       azkeys.EncryptionAlgorithmRSAOAEP,
			encrypted: "v3GX60vQLrsjW8tKEKT7Se6GwaJwZPxt7JT64xchvCIz7Bin+ehqv6IOxNZbQPSgMmLdxIL4VXjs5Yexeh/LWmGM25hrHoEsVyqVT4X2UD71USSrr/ftrEV/7exKy4xwqVv1Dyjvuw36nONGlkoYdZY9ZMwZgBZL0ZmaN5OoiWEmy1r8fJD1eQXR8tHgc0z7qxDrneZyRcqCAa8AMJFjzJ+aRrTnny5hqQ3/vSNZUXI+Bwv6mhw3UcKjFuUYV3kC8+h3FfK6+rbZOigr7V5uzBm0sj0yGw/UJI/pgio/U1l6kRXBUSefBHA3y59arZsvkjuWG9L8h1RZgR5bfWzkPg==",
		},
		{
			name:      "RSA-OAEP-256",
			alg:       azkeys.EncryptionAlgorithmRSAOAEP256,
			encrypted: "S4pzhGlZsdNskUwheWQSxaAR7ELBNimilET33Zz1261q9TFXo3XiTsFmOfVA1+xlzC59T3T1t7d+x4c8bEBEACY/x5YKxB/a64hxLc3SUdx+MxhNrZgiuRFK28s0zD3ReKrGuPcUPJhn6SROSmO2AQ2J5EHKCVgOmct1huxZMpRPlxJuFZ3bLk4eKuixoHt1hXPmA1oHeVagDhlm1+dbAFDhYbLkZnEl19/uNgO+oqOxR54lJqWQNPNSY4hRn7WGv60eIqMHZ44dtjBAwNWQA833zRCI8ihPSnz4miULlWS9BEfk2khKsqkVYotFNEjKIzp5fJNFIuxFnu8M1eGp8Q==",
		},
		{
			name: "missing private key",
			key: &RSA{
				key: rsa.PrivateKey{
					PublicKey: testRSA.key.PublicKey,
				},
			},
			alg: azkeys.EncryptionAlgorithmA128CBC,
			err: internal.ErrUnsupported,
		},
		{
			name: "unsupported",
			alg:  azkeys.EncryptionAlgorithmA128CBC,
			err:  internal.ErrUnsupported,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encrypted := test.Base64ToBytes(tt.encrypted)
			rsa := tt.key
			if rsa == nil {
				rsa = &testRSA
			}

			result, err := rsa.UnwrapKey(tt.alg, encrypted)
			if err != nil {
				require.ErrorIs(t, err, tt.err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, key, result.Key)
		})
	}
}

var testRSA RSA

func init() {
	testRSA = RSA{
		key: rsa.PrivateKey{
			PublicKey: rsa.PublicKey{
				N: test.Base64ToBigInt("44GgROme67hskskh+3UYSZ0rg9z9xvf2WkkglOMoaZtCTZEN3s5vMqV81RaSlo9EerhpONCfs9QItHHum69US0sj5sXUE6k/wp7aNfx05aFbpDvoF27a0/mTLCcvChRGUucRUaNldycC4UgD9yQFB3o2Be08oxD9CCbwiBjZAmPV39kD4XRTLNfrmKLfxbzn/n+zGmhig8/P9Ww7oWo/I4rl/hHXSSL+xqVmVh+Vm2/JRvuK0AGE8QBI7W72k3wT0NDie3k0L9vudOg6YOwLD6uCRmxhm4anTeF+F48RymMtbAxZpsCf0pFSyXHQ0Rk/Tef1NlCSlRk4J0mIQgQAMQ=="),
				E: 65537, // AQAB
			},
			D: test.Base64ToBigInt("hHZe6IDVxQ12Oejd3lkJMSNPyNEM+aI6T8swK0AvsX1yl1MTrlynpedwzWj9JKh6CLICoc/mjH+yKc4ETaVCASzY1G7u0hvDQf/XsYMyVNkkUHWI5svmoXE43YZa/xVa9L4Q+WWXmE6ggKa7mFPikb34Ym8E1TT4/pwdhEBjad26Cymm9jPB4be8wiKjcTDiwkGtEwmZ2K6hLTITdolsgWOXlCKel2W7y/yjz8JWgTB6lFnEvBXNjN0RZq9z7fSAJP+cuMw2y0AcPrw2m6wuYuB9m0qBpMAUokoFwhvYpUQi89wW/yKxmxBSk4y0SWmq50Y+s2vnhl5aIFMBJGDV+Q=="),
			Primes: []*big.Int{
				test.Base64ToBigInt("8HlC+Z4XXN3FfKOLeJecbOQuAgeVBT8cECMk7f0RXAlXOSYQzH/5n91bE9GNVdiWBT5nkquz0Cg2DJzDHiUY3jal3g+Ae9kyXbrspas1TXF4OTT7Zc3mp/vkSoPegFKUqUe8wHeRgdW3Jr7HPh+2JFRSEw68wRWimhd4J1uFHsc="), // P
				test.Base64ToBigInt("8jIHvhPKuE7tTYw1MZA8f23bIrtSsbf8SZIXo3Vuq7ijwwMPji/mdgutbaH7eG2WNU1DCeh4M/6y7Ux+GYZ/IaBXhrvNP7OrTLSczSIBHZ2r0Ku7om5+dOz2GmQBU1J/7RVNf9tFR02TI977gsdMgeyTaikdzTc8U6ev/CZI0Uc="), // Q
			},
		},
		rand: new(test.Rand),
	}
	testRSA.key.Precompute()

	assert := func(component, expected string, actual *big.Int) {
		b := test.Base64ToBigInt(expected)
		if b.Cmp(actual) != 0 {
			panic(component + " not equal")
		}
	}

	assert("DP", "xP0w5jahQMvTGVUHzZO06mbJYZRAePnHzVhcyjAC5ngoYYJTRJKZNGIqV8PTmb1At671PWs2c5BdJlvMYodVJcNygMQGJm44Ghwj+1qS4YvQRlymjDDtgDKSQpBf1pLPgRRpBOlt4wPlcvHZWYS0unHwgfgSm8FTYBNVtDf+hsU=", testRSA.key.Precomputed.Dp)
	assert("DQ", "beum9+2jo+KucPOhcM01p+AEBM9fyKjoJ7vWXql9gRJbwLYy6SV0Qz8phwhtSUrzUV2vf1+yrmZ6bpi44nzYVjqfftbdYHv60uVmBPPZ7ccRo7NNhXsAibDCQVgCAf7/cGqqscyitKnQjgc1vzUU1CK7BQOEMw9OoekJRjdZ9SE=", testRSA.key.Precomputed.Dq)
	assert("QI", "wbyl3nbTqBKqgrqv4M69x60UhNoL7Uxk4pgszGs8hwsB3AS9RKY/obm15J7kdSeBURPuQyekp/AHeZjZwEZXn7uOahoMqAPU0oNPlstFW/zxf/806eDGGr3UK+4ANjbEq8B093fX51rjY9x9ZTn1kFQ3SZE6LFg6IDggKQJTlNY=", testRSA.key.Precomputed.Qinv)
}
