// Copyright 2023 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

// cspell:disable

package algorithm

import (
	"crypto"
	"crypto/rsa"
	"encoding/base64"
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
			name: "with keyID",
			key: azkeys.JSONWebKey{
				Kty: to.Ptr(azkeys.KeyTypeRSA),
				KID: to.Ptr(azkeys.ID("kid")),
			},
			keyID: "kid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			alg, err := newRSA(tt.key)
			if tt.errMsg != "" {
				require.EqualError(t, err, tt.errMsg)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.keyID, alg.keyID)
		})
	}
}

func TestEnsure(t *testing.T) {
	t.Parallel()

	sut := func(src []byte) []byte {
		return ensureSize(src, 4)
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
		name string
		alg  EncryptAlgorithm
		err  error
	}{
		{
			name: "RSA1_5",
			alg:  azkeys.EncryptionAlgorithmRSA15,
		},
		{
			name: "RSA-OAEP",
			alg:  azkeys.EncryptionAlgorithmRSAOAEP,
		},
		{
			name: "RSA-OAEP-256",
			alg:  azkeys.EncryptionAlgorithmRSAOAEP256,
		},
		{
			name: "unsupported",
			alg:  azkeys.EncryptionAlgorithmA128CBC,
			err:  internal.ErrUnsupported,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := testRSA.Encrypt(tt.alg, []byte("plaintext"))
			if tt.err != nil {
				require.ErrorIs(t, err, tt.err)
				return
			}
			require.NoError(t, err)
			require.Greater(t, len(result.Ciphertext), 0)
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
			signature: "fZHI0GTnRDYXiSYR_LXTXkc3LsqAXDygcg3Nako_raHbBjZNZkbAwSXNLx2ukFui1K5QydWbtRKlfpYaw7JAJYxXqGe6M_KSUgqhA7dtb2kaHXTBLG_tjEu5VAXcfxDCrPby_FAEllQ2XYGOFEFU8IRW_AiB3gL4BSs0ZmZsA_HVHfCSLKdUMCus5YhsbkkxWp8IQuKPH2QSvH0nIRfRaJHy60PEK3Z5aqEJcLb46Nq0H2o7H0jzX0lZDt_7_8xCgpzYOdPHvvfPHSGMv2LTDddIdD46_Lmh4zPewPW3C8tsuXMhpq7Ey9qbxivzWNjbI5WJuA9hfQhSy6PWEpjy_hVuyUercvCs2EPYCeNRCq1SUNG-3AU4P9j8cHD-SI-MDfjZKE31yBQ533tG6tVF-xDawYJTypkuUAlI5Q-WUTiP-Ra-qZ6H-wP6VPivE6LkqmYGyCPT_GkBFku47jIymC8pcMWrvFNd0DEVbojD0tdEwzXK-Wv5cHGLK7LkIORfWUGm0JpmOWD-JE8uWTNxjoOAPotI2MJH8BCmQQrh213DkMRfBJ7t3QFwForKLN3kRKi69waNa_rJzUHnNHlq_YowhR33pTZq72_dMg1zfSAESB_BBYlzfHYd_GP43lAmJfVOi4jGCDSgVCV-0xomNR8OBAtIsIHZ_v2tJ6nLY10",
		},
		{
			name:      "RS256",
			alg:       azkeys.SignatureAlgorithmRS256,
			hash:      crypto.SHA256,
			signature: "OSuHMKNPnAvjHCiihnkmyl8soY8ZkV4oE08Xkssb1o-7Ktf4yWxuusyVF0mc_4xIwQ_0e_oE6jM8Mwa-51Hx77FBUPA2yUTCAzSQwGbtwsMdI9z1DeM3tIXcrxlO4P5cFH_2c0-E9d1jPChGFy1FZEQ6z9Pnq1W5aXd_ys65LL81maUYgvIUllTZJRySlbuLjS0vemmVuPLScRgIsyBcJj68XHvWlgxuN1IlqsRfBgVdbQ9C2mkXL2wJRePZBC_jpJ81JkAYMbVFEZd_Or4dhQmR9vy1cqDiwlXW3uU_jcogFg0OaqS67b-e0ICvnhMbmfMs3tlELxGVibB7rMscmQNOSKhz8iACvGS9HSEc6f6-7EBbsjWYm6QP3Xpw8YRRIqvIL6yregJ8An6ZpPz1CA-_9YUOfh6ys6QaiDAgG5YVfkuUptVzYNUkbWQxkUaeccPZa0pg0biC9c6zPVCxw89hhGvoewXAyO8O0CI_UEHx3CCYlIse5tZsEsNYycR-oono3eZydOc6vrYnADf7ZWfmanD9PrQBcAH4m61Pd_W4jdknZ2LdoYQFWmNCFg9dzqWW1AtD5JOuqko-NOx9nN8LJ6qz_kW0Vu4TtYYkLvt5T6jJocwr7c4udu1NUpLRmpN6PDnBeFD64Y_EEWDPY-ccxdxDycWsAq5CcUjRLRg",
		},
		{
			name:      "PS384",
			alg:       azkeys.SignatureAlgorithmPS384,
			hash:      crypto.SHA384,
			signature: "kfdcpn4tlnWaeacbOJMnw1Ld_naFe9Jr3-FupEQv3s5MvTzboDVp3w_pDQb463nflc918KMPtAcDjuOyVvlIL4IbX5DHLhF9XABKPdRRkzPd7ERcNzVVDYd9iFaBpjV56RLW8QxVJwhHKcMKx3tGJJ9lqw0Nf7WEYLdf0B04tBoQCQaM-hBAZ--_2vMe5YVd-sL9ci6SSYEKNOEIYJnBHO1mAGS8fml0oD9cLiDcdt96TtzfhPon2NqEZlV0XhYQxNpcKU2CwNGsz5Ytl4ucjulBbdn1GxSebmFMwVYBHlyn41yARilEEY-Y8M0fjjDJ8b2z5a79AGB9qdRdYLVXDYxAanwQRVNv7FWfQZZcdq77JI6d6zhA-wnTbFRDhnBrvZuu1c2pJK8HiylHhBPpEpXHFtepSo--110_n8McQ6YWPuLoFSNnv3eWSreX97fARXn-Hf9Fcpd1PsZgVpcHfL8fbUXjdiFmeZhQzOIEMWvd5W2V1v1TSxWvStySKCv4F7_yuCkVHZYq72sPvqkOEnDWM0s3r4ZDPAsG-E4OsRhWOUfs0enj8ZlHAE1vugYv_uFbC-tib1qYGeQH-0Xz1spbyc5Rxh5Vx-ZeZOOV1nTwdqtZRsI97C96EVtlpQmv5NFSyAyI2F282wGTRHtvMZboAOeyMoOLmDrHZkYOdKY",
		},
		{
			name:      "RS384",
			alg:       azkeys.SignatureAlgorithmRS384,
			hash:      crypto.SHA384,
			signature: "Uwr2N7pyKaqv_pLWV4AM07DVXptrA0xMh-oKAtlJfl8GHtD9gtxyWa82GAVrqh86G8pm0ki1f2PqTBcT33Mu3tJB6fgTOZu8jZqX0lp7SOd3T9nNC5VT5-eKYNGaVhPIZOzhioB_dC-Z1kC8r3qBRp3jLuSVj9nCmLLFo7dh8pBSBzyDG11luY5yCbN7aBbIhZi9Xy-nSLX5TMfI0oqe_4kBCOcZrRUdsxE9voZjmVp_3Xv7YTAnz0HEzCLyraDaH_a3BygXEEpNXbkhzyIehYpii1sH7K7PiDxPIlTejS0jRphVs4avF0fV51wZQzdlW1I2yWDG0EO5vXkvpHi-P_rsX-QL0BEQKTXYiuXv3AjevcPMl7vIIdpFf_ivnFhCluyKL6yKiA_FerpRNmfUSVAmvQTdZMyK9jTfQ7klUPeT3PA-3H-LKPTCudVPUp2bR6veXrndo6igegytMcMXnALIiLTZyKMGh4Q0Fjm5NJ3yLBgkYnVC5pMIVMERqKKR1PEUJnA6sITZszKiVXYqDc7H_oY8evNBjdn5A4tgH7kbHZ_be66kOnEcJ8EHrQlsji1c6AE3XCc-6zLhkMkJsCq2mcZdItgZUiB0dJlTbwe9po8s9739bpbUH1TqPjPilfY-QrKFvK4SzRF18kJ4p84-L4taF6rKRVjHDsZ_HMM",
		},
		{
			name:      "PS512",
			alg:       azkeys.SignatureAlgorithmPS512,
			hash:      crypto.SHA512,
			signature: "cpm_ZnUUCrlevZYHL7ekZ78UVLoSHXHHWmMghcdrp7087YHh49VjlX--p00z2Pwbz_oJIaPhA8QdWOvP9xneL33HuS9bphc7xcXlQj62HQdpO0SdwLJd4bZ3mXrGpmFwRAGjQt85lQPObLrr8NUQv2C7eS9qjzZnHlOiPYSckCb-R6MadPHk752GYa7FbpxwYeuYSy_6QuU34OE7euAwZSQnaovJFjBd6dNNrV_jHNlSWVk4YfM5pP5mdw6-1MX1sYZQCY4Z-XK3tXFIcN627j0UiKMoMvIviOjK5r2KYdY2yB_80ORwdWtx7q4Pot1BUstlFoVN-G6tJSdKIdqj7ivyL9nzyfqg4De7w5nCWQxkCwfbGReJFKI3P5nRENild-pejkN9F5Xx3poWGkdIRZoy46ug5Rjjcjz78nL_mhqp3hDDBn5akvbZy7vZgdSpdh4mcG5c0SZJWDvdLeSu_g9Y1uGeHQ42szoGYcHZ7sQNUwwzn4J5lxecG2tARBew-Jk0rqXAPLM2fTUIWnecjKPvAd_UqIdCZl-BZnoemC81LeTYVitOaPtBHYbbaTmiKbmeoiNfPV5KFK61Pzgu12ypxwLvBtZgoRSH1OLHsMrfxjo3hL0ijZcjmEGOF6i15_6gTshFhqFMI2D7OntCE-m26pLpdt21VjkVV_uObWk",
		},
		{
			name:      "RS512",
			alg:       azkeys.SignatureAlgorithmRS512,
			hash:      crypto.SHA512,
			signature: "Ng5oswYWH2QiHtjzr90kZyqYLmuL3TtpqcOLYC6lhlcpbp5nYtgKw1blHiLq6GkhVa71RJOUkZ1d0r7-K93zcqbxRnLeK4dbcT7AUMHPxNvnVugfwcyskk-hiEAYtOrHuKt0LkE8pmq4IGGooiU_UPQJpgm2o43z7sIndSe6Raj1XbLD_TIEHFw0JYrQTYt0d0ZRKyNPQViSnKNSuWiLi-d8SeCf7gfPsMlIuDgl1AVqOQveO2bn-JAgQnZ9xdMsVU-sUhJDfnHDhVfk_9Qv3HhdzDQ4-CMJUSlOkukK_xXI-eAV6z2pzyDv3xpmYWKJHXoQp8QNaFM0UqSJos94Y920W80ZtqJpheP4WnGK5R-7aHBwX_yjUotCMCKG5aWEPOU4Qvt4I3vFRKo098O2biHZlOh8vektrTvtnqZfbCW4uylyfjGo0IcunIa-odHq5nOv7J56h3DtvPD_ZZqFGECnHIqYT7gvCbGK79Mfg89wCNNwhJH5TnwhcDORugAeKOSF0I91KhpZZt7hesuO9OfKD76k0o1rxFrGsd782uzhuqwJzqgVoQMsBr-CglLzDOA_uQpQT2ZLXoRIoS_b0MkdtLXcu9_ecOEhVfW_EJWprvarm4u9c6XkVMZB3Em99xuhaY33LGc-Mvwyw26sNGCFFCk2SqUymxZjPmIUkOY",
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
			signature, err := base64.RawURLEncoding.DecodeString(tt.signature)
			require.NoError(t, err)

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

	key := []byte{0x6d, 0x6f, 0x63, 0x6b, 0x20, 0x61, 0x65, 0x73, 0x2d, 0x31, 0x32, 0x38, 0x20, 0x6b, 0x65, 0x79}
	tests := []struct {
		name string
		alg  WrapKeyAlgorithm
		err  error
	}{
		{
			name: "RSA1_5",
			alg:  azkeys.EncryptionAlgorithmRSA15,
		},
		{
			name: "RSA-OAEP",
			alg:  azkeys.EncryptionAlgorithmRSAOAEP,
		},
		{
			name: "RSA-OAEP-256",
			alg:  azkeys.EncryptionAlgorithmRSAOAEP256,
		},
		{
			name: "unsupported",
			alg:  azkeys.EncryptionAlgorithmA128CBC,
			err:  internal.ErrUnsupported,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := testRSA.WrapKey(tt.alg, key)
			if err != nil {
				require.ErrorIs(t, err, tt.err)
				return
			}
			require.NoError(t, err)
			require.Greater(t, len(result.EncryptedKey), 0)
		})
	}
}

var testRSA = RSA{
	pub: rsa.PublicKey{
		N: test.Base64ToBigInt("tzFeRPTTKru13TcHYp0YvfPBs4EthI/iUZHkfT1n93OeRQMtNdxVqi6axRAMVBprSBXE35axxivTV+nGezJpbq+JJfVRiY9HBDpxtmpY3ikRB2Pr7DatxFABF6IbfPSsQmKGUsjTJWwSDdYLgtzZmhpQmbUfXm2MCausYzC+yIkFy8PbcS+ouyeT1LGCJXziQU37pUHXrEFfXav8Q5SRMbk74HtWqqI1Hx0IssC+Bj6Wp0wrM9QxRQiArOnJ61nuzApUarnYT7xr0Ft3qiex8lKmhZ52mK0JvRlzXuSaSZ8KH7BJ5z09vJFLX2eEOBuiM/wOdmEdgHcvlv0TLn6uYYmXuwhtMr8FvV7TPs0CK5fCl3SBsmdnlh2+7XNMg9o6hkcpbzL2dTdnfscVOtUGhh7ypftCNnPy219knPwlzYcTuNovoBAvrmBTJOlJhXx/9qHyE+Ig/MdtXuh19sohUnls6fdIiBVqHRfhNewOPr7wURZGG58S4zHk+RB5k+5pONtf1lb7+dLwrG0xtgqV6dobcJUYYkKJlToHmT1ApquROZt1hnRvIr72aKiRCWNViwlK0yBQ4c3giyzB5xduDLAUiWOwxYU9Lr6shNAMQ8A3JHARgQakh3UqAE0rNLLqrNGVKEpUtxBcLxRqR2v9y91dhiXmEAiG8gEfnrSRAsU="),
		E: 65537, // AQAB
	},
}
