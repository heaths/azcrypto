// Copyright 2023 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

// cspell:disable

package azcrypto

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/h2non/gock"
	"github.com/heaths/azcrypto/internal/mock"
	"github.com/stretchr/testify/require"
)

func TestNewClient(t *testing.T) {
	credential := &mock.TokenCredential{}

	client, err := NewClient("", credential, nil)
	require.Nil(t, client)
	require.EqualError(t, err, "keyID must specify a valid vault URL and key name")

	client, err = NewClient("https://myvault.vault.azure.net", credential, nil)
	require.Nil(t, client)
	require.EqualError(t, err, "keyID must specify a valid vault URL and key name")

	client, err = NewClient("https://myvault.vault.azure.net/keys/mykey", credential, nil)
	require.NotNil(t, client)
	require.Nil(t, err)
	require.Equal(t, "https://myvault.vault.azure.net/keys/mykey", client.KeyID())
}

func TestClient_Encrypt(t *testing.T) {
	const (
		host = "https://test.vault.azure.net"
		path = "/keys/rsa204/ca393a58beae4589bcfbf8120d0e9671"

		plaintext = "message"

		rsa15base64url      = "TQfQEkYPWUMkeVcgXHcxB-6Odnvgd42e6YDVipRNUHjA_A8y-ejD17qXX7eV58B2kRikBF7VznGf44vEw7pTZ2a0QVVmZj0vWEiKc_eEhqPem16Tlz4iSlLMRmXf25pZd9kRApj__ofIBjWvfvci2UgWlO3HLrOU7q9qShZgxM2V2OcH8XIKdTq9BHMeJQ3OZSPG4dT5H84wd-r925Kyda_WCWihX-0ZvPU6mjm0O05OFm3Ojtdl2C1xGwByAIhhUvExEIsJSBLkTtL-peAaA4CrDg-foBrUMvrqO-YWg1tJQ_5mMjhVWtB3NQpPc-Soo4IhwFmfWdBK2PzMeG7xaw"
		rsaOAEPbase64url    = "CxwLeizTKykT5f029SolpRgPP58I032lF7BysR4U2_MoeuGzFzdqdQc2Ad8p7tEIXRF5cnRoHZZqFQHmhwY41005x18sTOBVlP8XuNL_w-YSadjzlT_Dp_TDPahbTGHkwj6yFIDKfNpT11GaiUi6iDZ_b8dYebx2o3761agOTUZWK92b-nKcmedgh2q3w3AHCvibm2gBfgGNKGBy4pK1XbVJKNCiBNW5KA02GFov-fJgqEKlV7c9BHzZdER9m752bKN9bA43J-M-NK8zI9mSQrqS76JihMVeA4JcdM5pEbuLev7PEgexX0DjzAEMgvsYRGOtTUI9L91ElZNEsiUPNw"
		rsaOAEP256base64url = "fu-UXk52z-mN1Ult7b6DS6xIrN8RPA61Zy1LRvbPps9UiomMDkHoq3yIq3ddkCqS6QGmqgUQtcWYt40WJubZ2Dw_Xc2W1yr_t2jSP_12JgxaUPWK9Ie1OLhMSI7-BMnKHN05X6KTfA5vSaZnMuOg6TU3ZK0E4Q1OF86n2HtDoQOB7lk3j0MiZgtWNdfyQ8jt5Na7rcFD9NbyoFJQ6dAS2kzhAdG9S4qVY7nWc5cnl8yUYPQYeqWUsTV8eV27s40hgvsh7qMCIaquLq4dAPrZM3ftm4qaQpv91jpwNk6McJiiSomhQflJ9H6oQC5BjvOz99KXNkX5sXQJuDhXD0JK0A"
	)

	type encryptResponse struct {
		KID   string `json:"kid"`
		Value string `json:"value"`
	}

	tests := []struct {
		name  string
		mocks func()
		alg   EncryptionAlgorithm
		err   error
	}{
		{
			name: "no get permission",
			mocks: func() {
				gock.New(host).
					Get(path).
					BodyString("").
					Reply(401).
					AddHeader("WWW-Authenticate", `Bearer authorization="https://login.windows.net/tenantID", resource="https://vault.azure.net"`)
				gock.New(host).
					Get(path).
					MatchHeader("Authorization", "Bearer "+mock.TokenBase64).
					Reply(403)
				gock.New(host).
					Post(path+"/encrypt").
					MatchHeader("Authorization", "Bearer "+mock.TokenBase64).
					Reply(200).
					JSON(encryptResponse{
						KID:   host + path,
						Value: rsaOAEP256base64url,
					})
			},
			alg: EncryptionAlgorithmRSAOAEP256,
		},
		{
			name: "rsa15",
			mocks: func() {
				gock.New(host).
					Get(path).
					BodyString("").
					Reply(401).
					AddHeader("WWW-Authenticate", `Bearer authorization="https://login.windows.net/tenantID", resource="https://vault.azure.net"`)
				gock.New(host).
					Get(path).
					MatchHeader("Authorization", "Bearer "+mock.TokenBase64).
					Reply(200).
					JSON(mockRSA(host + path))
				gock.New(host).
					Post(path+"/encrypt").
					MatchHeader("Authorization", "Bearer "+mock.TokenBase64).
					Reply(200).
					JSON(encryptResponse{
						KID:   host + path,
						Value: rsa15base64url,
					})
			},
			alg: EncryptionAlgorithmRSA15,
		},
		{
			name: "rsaOAEP",
			mocks: func() {
				gock.New(host).
					Get(path).
					BodyString("").
					Reply(401).
					AddHeader("WWW-Authenticate", `Bearer authorization="https://login.windows.net/tenantID", resource="https://vault.azure.net"`)
				gock.New(host).
					Get(path).
					MatchHeader("Authorization", "Bearer "+mock.TokenBase64).
					Reply(200).
					JSON(mockRSA(host + path))
				gock.New(host).
					Post(path+"/encrypt").
					MatchHeader("Authorization", "Bearer "+mock.TokenBase64).
					Reply(200).
					JSON(encryptResponse{
						KID:   host + path,
						Value: rsaOAEPbase64url,
					})
			},
			alg: EncryptionAlgorithmRSAOAEP,
		},
		{
			name: "rsaOAEP256",
			mocks: func() {
				gock.New(host).
					Get(path).
					BodyString("").
					Reply(401).
					AddHeader("WWW-Authenticate", `Bearer authorization="https://login.windows.net/tenantID", resource="https://vault.azure.net"`)
				gock.New(host).
					Get(path).
					MatchHeader("Authorization", "Bearer "+mock.TokenBase64).
					Reply(200).
					JSON(mockRSA(host + path))
				gock.New(host).
					Post(path+"/encrypt").
					MatchHeader("Authorization", "Bearer "+mock.TokenBase64).
					Reply(200).
					JSON(encryptResponse{
						KID:   host + path,
						Value: rsaOAEP256base64url,
					})
			},
			alg: EncryptionAlgorithmRSAOAEP256,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Cleanup(gock.Off)

			if tt.mocks != nil {
				tt.mocks()
			}

			client, err := NewClient(host+path, &mock.TokenCredential{}, mockOptions())
			require.NoError(t, err)

			result, err := client.Encrypt(context.Background(), tt.alg, []byte(plaintext), nil)
			if tt.err != nil {
				require.ErrorIs(t, err, tt.err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.alg, result.Algorithm)
			require.Equal(t, host+path, result.KeyID)
			require.NotEmpty(t, result.Ciphertext)
			require.True(t, gock.IsDone())
		})
	}
}

func TestClient_Decrypt(t *testing.T) {
	const (
		host = "https://test.vault.azure.net"
		path = "/keys/rsa204/ca393a58beae4589bcfbf8120d0e9671"

		plaintext          = "message"
		plaintextbase64url = "bWVzc2FnZQ"
	)

	type decryptResponse struct {
		KID   string `json:"kid"`
		Value string `json:"value"`
	}

	tests := []struct {
		name  string
		mocks func()
		alg   EncryptionAlgorithm
		err   error
	}{
		{
			name: "rsa15",
			mocks: func() {
				gock.New(host).
					Post(path).
					BodyString("").
					Reply(401).
					AddHeader("WWW-Authenticate", `Bearer authorization="https://login.windows.net/tenantID", resource="https://vault.azure.net"`)
				gock.New(host).
					Post(path+"/decrypt").
					MatchHeader("Authorization", "Bearer "+mock.TokenBase64).
					Reply(200).
					JSON(decryptResponse{
						KID:   host + path,
						Value: plaintextbase64url,
					})
			},
			alg: EncryptionAlgorithmRSA15,
		},
		{
			name: "rsaOAEP",
			mocks: func() {
				gock.New(host).
					Post(path).
					BodyString("").
					Reply(401).
					AddHeader("WWW-Authenticate", `Bearer authorization="https://login.windows.net/tenantID", resource="https://vault.azure.net"`)
				gock.New(host).
					Post(path+"/decrypt").
					MatchHeader("Authorization", "Bearer "+mock.TokenBase64).
					Reply(200).
					JSON(decryptResponse{
						KID:   host + path,
						Value: plaintextbase64url,
					})
			},
			alg: EncryptionAlgorithmRSAOAEP,
		},
		{
			name: "rsaOAEP256",
			mocks: func() {
				gock.New(host).
					Post(path).
					BodyString("").
					Reply(401).
					AddHeader("WWW-Authenticate", `Bearer authorization="https://login.windows.net/tenantID", resource="https://vault.azure.net"`)
				gock.New(host).
					Post(path+"/decrypt").
					MatchHeader("Authorization", "Bearer "+mock.TokenBase64).
					Reply(200).
					JSON(decryptResponse{
						KID:   host + path,
						Value: plaintextbase64url,
					})
			},
			alg: EncryptionAlgorithmRSAOAEP256,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Cleanup(gock.Off)

			if tt.mocks != nil {
				tt.mocks()
			}

			client, err := NewClient(host+path, &mock.TokenCredential{}, mockOptions())
			require.NoError(t, err)

			result, err := client.Decrypt(context.Background(), tt.alg, []byte("mocked"), nil)
			if tt.err != nil {
				require.ErrorIs(t, err, tt.err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.alg, result.Algorithm)
			require.Equal(t, host+path, result.KeyID)
			require.Equal(t, plaintext, string(result.Plaintext))
			require.True(t, gock.IsDone())
		})
	}
}

func TestClient_SignData(t *testing.T) {
	const (
		host      = "https://test.vault.azure.net"
		plaintext = "message"

		ecpath256         = "/keys/ec256/d66bce8f4df64a9a9e172239d9f62572"
		ecsig256base64url = "bx69NxzK4aRVu3CcW7LD6Znt5-00uOXj05lFCPI4wzxI-XnJhhgva4970_snfMOmwQ9C7pBtGEINbueJVyD8qA"
		ecsig256          = "6f1ebd371ccae1a455bb709c5bb2c3e999ede7ed34b8e5e3d3994508f238c33c48f979c986182f6b8f7bd3fb277cc3a6c10f42ee906d18420d6ee7895720fca8"

		ecpath384         = "/keys/ec384/7e82704e15b049d1b5f3e9953ad5403c"
		ecsig384base64url = "Eb6cSdVc_qmfnSKx_a7WfLvaKLBFje5Y-4FsO0K2oBujHLM7a246L-CkaXAd85vJrJMmKoiL8BSaUGVfOBdhUYGM2WKoLfcOzrxhLTGmqaJgQ_SVpwzqor9g_1X76aD9"
		ecsig384          = "11be9c49d55cfea99f9d22b1fdaed67cbbda28b0458dee58fb816c3b42b6a01ba31cb33b6b6e3a2fe0a469701df39bc9ac93262a888bf0149a50655f38176151818cd962a82df70ecebc612d31a6a9a26043f495a70ceaa2bf60ff55fbe9a0fd"

		ecpath521         = "/keys/ec521/781a62b96fea441095edf3a115c94c5f"
		ecsig521base64url = "AaZsoVz1dt-1wYiQ1VwIpD_08puGyvRII5tW0JumWLa8g87pJlWYJXihb10t_UAT-_ECEBncj82CVoRTeSjptMpWAb9F8mXKSuk_iJyDuOBIcKtFlfk1d7sgEDMxtoB34inrPXGg6eqvSgJ3k3xbPL29U54fIa82C6wwvtNopSpp5QTr"
		ecsig521          = "01a66ca15cf576dfb5c18890d55c08a43ff4f29b86caf448239b56d09ba658b6bc83cee92655982578a16f5d2dfd4013fbf1021019dc8fcd825684537928e9b4ca5601bf45f265ca4ae93f889c83b8e04870ab4595f93577bb20103331b68077e229eb3d71a0e9eaaf4a0277937c5b3cbdbd539e1f21af360bac30bed368a52a69e504eb"

		rsapath = "/keys/rsa204/ca393a58beae4589bcfbf8120d0e9671"

		ps256base64url = "JwsvM7T86LqjFmdMZAxc-Klm7qN8XPTL6ukpOieMF0o_hhZ2E-6feT8YLiQbl2FOzlajZFQvwgDxGKlouzZTggRTI4w1qmdUJvo6BGoiixL8eGULfCPZCWs_17GhJEhr8GSANhrrgtn0JStUrulQp6WWvRMCSqzAUm1gGXBYNNrV8IHu7L9M56z4WGuv6ghz-1f-5TMP9ZVmMxBSdwuB-DggY037cHcLB8RZSfqXAz8ZxiblUEHSeC7bLcS2KmCbWfn2c1r45OsPlKmouXf5Mvr1O-7ZFezJbTJ6BwqgKkK0ogOCcuDsEUtwzDQDj4_FO_3slBdvAqgynf7pn3tyWg"
		ps256sig       = "270b2f33b4fce8baa316674c640c5cf8a966eea37c5cf4cbeae9293a278c174a3f86167613ee9f793f182e241b97614ece56a364542fc200f118a968bb3653820453238c35aa675426fa3a046a228b12fc78650b7c23d9096b3fd7b1a124486bf06480361aeb82d9f4252b54aee950a7a596bd13024aacc0526d6019705834dad5f081eeecbf4ce7acf8586bafea0873fb57fee5330ff59566331052770b81f83820634dfb70770b07c45949fa97033f19c626e55041d2782edb2dc4b62a609b59f9f6735af8e4eb0f94a9a8b977f932faf53beed915ecc96d327a070aa02a42b4a2038272e0ec114b70cc34038f8fc53bfdec94176f02a8329dfee99f7b725a"

		ps384base64url = "2eLNue-wg2wt3ixmD1QND3OFzo496g35QyOOzii52R1AQByxi4Ui1IRzxcFqzgr3Xkf4ST2Y1pwI-78NXR8SdLQYlBy3TRijPqQ3N3gSsUZ8NpMjxP0afzSvolgr1lFIMFZqXX4CgL3KP7AQ8wj9ktykpsXurnDquqSJ0fKzLmehwx23vvyYkKvd27gi-qbysHRcoOx6aRO3I4ldmFkS4whqvy-_Vaq2fnr4WEKiQ8scy2rRDUmRgxpikiKCqj9OvOk22krjQr0Qfvix1qutoLVrwJpMcLh3GjKEyj41rgD8vmtHsjYw0i9YaJG7Fc7iBwr5o46kU0KCs7Wjx40f-w"
		ps384sig       = "d9e2cdb9efb0836c2dde2c660f540d0f7385ce8e3dea0df943238ece28b9d91d40401cb18b8522d48473c5c16ace0af75e47f8493d98d69c08fbbf0d5d1f1274b418941cb74d18a33ea437377812b1467c369323c4fd1a7f34afa2582bd6514830566a5d7e0280bdca3fb010f308fd92dca4a6c5eeae70eabaa489d1f2b32e67a1c31db7befc9890abdddbb822faa6f2b0745ca0ec7a6913b723895d985912e3086abf2fbf55aab67e7af85842a243cb1ccb6ad10d4991831a62922282aa3f4ebce936da4ae342bd107ef8b1d6abada0b56bc09a4c70b8771a3284ca3e35ae00fcbe6b47b23630d22f586891bb15cee2070af9a38ea4534282b3b5a3c78d1ffb"

		ps512base64url = "WHERWyRNLXluXdvaIPN86xksP_0Co__cXQGWvE0GLFP_z3LEz2yz8l5qEDEKPkFv-LGXjPA2IY0kYCuhwsVfmSgvbDyVvrwbTdAJ7PtinW-SLgLDtS_AuUNnNXn9uvH2nTbivINEocJxR1IHiqki0eH81ECBIL8JED6BLw7yjrWr4Q2cSycJiN7ZZou1nTG9iqrK3AosKQw86Qr_2tcO3nvq765LFDN7AaVjZVdHlPJDrAWYpCvM4B9Is42-EohcZQ2waYWKW9JTPG4rFVPPn4XjSL0OsLFdI4FCrPP2Dnat8VDZsNj_2H5bmfp_SWsvhVKwok4eETT_WEgXZCCTsA"
		ps512sig       = "5871115b244d2d796e5ddbda20f37ceb192c3ffd02a3ffdc5d0196bc4d062c53ffcf72c4cf6cb3f25e6a10310a3e416ff8b1978cf036218d24602ba1c2c55f99282f6c3c95bebc1b4dd009ecfb629d6f922e02c3b52fc0b943673579fdbaf1f69d36e2bc8344a1c2714752078aa922d1e1fcd4408120bf09103e812f0ef28eb5abe10d9c4b270988ded9668bb59d31bd8aaacadc0a2c290c3ce90affdad70ede7beaefae4b14337b01a56365574794f243ac0598a42bcce01f48b38dbe12885c650db069858a5bd2533c6e2b1553cf9f85e348bd0eb0b15d238142acf3f60e76adf150d9b0d8ffd87e5b99fa7f496b2f8552b0a24e1e1134ff584817642093b0"
	)

	type test struct {
		name  string
		mocks func()
		kid   string
		alg   SignatureAlgorithm
		sig   string
		err   error
	}

	var tests []test

	type signResponse struct {
		KID   string `json:"kid"`
		Value string `json:"value"`
	}

	// ECDsa
	ecparams := []struct {
		name string
		path string
		alg  SignatureAlgorithm
		val  string
		sig  string
	}{
		{"es256", ecpath256, SignatureAlgorithmES256, ecsig256base64url, ecsig256},
		{"es384", ecpath384, SignatureAlgorithmES384, ecsig384base64url, ecsig384},
		{"es521", ecpath521, SignatureAlgorithmES512, ecsig521base64url, ecsig521},
	}

	ecmocks := func(path, sigbase64url string) func() {
		return func() {
			gock.New(host).
				Post(path).
				BodyString("").
				Reply(401).
				AddHeader("WWW-Authenticate", `Bearer authorization="https://login.windows.net/tenantID", resource="https://vault.azure.net"`)
			gock.New(host).
				Post(path).
				MatchHeader("Authorization", "Bearer "+mock.TokenBase64).
				Reply(200).
				JSON(signResponse{
					KID:   host + path,
					Value: sigbase64url,
				})
		}
	}

	for _, param := range ecparams {
		tests = append(tests, test{
			name:  param.name,
			mocks: ecmocks(param.path, param.val),
			kid:   host + param.path,
			alg:   param.alg,
			sig:   param.sig,
		})
	}

	// RSA
	rsaparams := []struct {
		name string
		alg  SignatureAlgorithm
		val  string
		sig  string
	}{
		{"ps256", SignatureAlgorithmPS256, ps256base64url, ps256sig},
		{"ps384", SignatureAlgorithmPS384, ps384base64url, ps384sig},
		{"ps512", SignatureAlgorithmPS512, ps512base64url, ps512sig},
	}

	rsamocks := func(sigbase64url string) func() {
		return func() {
			gock.New(host).
				Post(rsapath).
				BodyString("").
				Reply(401).
				AddHeader("WWW-Authenticate", `Bearer authorization="https://login.windows.net/tenantID", resource="https://vault.azure.net"`)
			gock.New(host).
				Post(rsapath).
				MatchHeader("Authorization", "Bearer "+mock.TokenBase64).
				Reply(200).
				JSON(signResponse{
					KID:   host + rsapath,
					Value: sigbase64url,
				})
		}
	}

	for _, param := range rsaparams {
		tests = append(tests, test{
			name:  param.name,
			mocks: rsamocks(param.val),
			kid:   host + rsapath,
			alg:   param.alg,
			sig:   param.sig,
		})
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Cleanup(gock.Off)

			if tt.mocks != nil {
				tt.mocks()
			}

			client, err := NewClient(tt.kid, &mock.TokenCredential{}, mockOptions())
			require.NoError(t, err)

			result, err := client.SignData(context.Background(), tt.alg, []byte(plaintext), nil)
			if tt.err != nil {
				require.ErrorIs(t, err, tt.err)
				return
			}
			require.NoError(t, err)

			sig := fmt.Sprintf("%x", result.Signature)
			require.Equal(t, tt.sig, sig)
			require.True(t, gock.IsDone())
		})
	}
}

func TestClient_VerifyData(t *testing.T) {
	const (
		host = "https://test.vault.azure.net"

		ecpath256 = "/keys/ec256/d66bce8f4df64a9a9e172239d9f62572"
		ecpath384 = "/keys/ec384/7e82704e15b049d1b5f3e9953ad5403c"
		ecpath521 = "/keys/ec521/781a62b96fea441095edf3a115c94c5f"
		rsapath   = "/keys/rsa204/ca393a58beae4589bcfbf8120d0e9671"

		plaintext = "message"

		ecsig256 = "6f1ebd371ccae1a455bb709c5bb2c3e999ede7ed34b8e5e3d3994508f238c33c48f979c986182f6b8f7bd3fb277cc3a6c10f42ee906d18420d6ee7895720fca8"
		ecsig384 = "11be9c49d55cfea99f9d22b1fdaed67cbbda28b0458dee58fb816c3b42b6a01ba31cb33b6b6e3a2fe0a469701df39bc9ac93262a888bf0149a50655f38176151818cd962a82df70ecebc612d31a6a9a26043f495a70ceaa2bf60ff55fbe9a0fd"
		ecsig521 = "01a66ca15cf576dfb5c18890d55c08a43ff4f29b86caf448239b56d09ba658b6bc83cee92655982578a16f5d2dfd4013fbf1021019dc8fcd825684537928e9b4ca5601bf45f265ca4ae93f889c83b8e04870ab4595f93577bb20103331b68077e229eb3d71a0e9eaaf4a0277937c5b3cbdbd539e1f21af360bac30bed368a52a69e504eb"

		ps256sig = "270b2f33b4fce8baa316674c640c5cf8a966eea37c5cf4cbeae9293a278c174a3f86167613ee9f793f182e241b97614ece56a364542fc200f118a968bb3653820453238c35aa675426fa3a046a228b12fc78650b7c23d9096b3fd7b1a124486bf06480361aeb82d9f4252b54aee950a7a596bd13024aacc0526d6019705834dad5f081eeecbf4ce7acf8586bafea0873fb57fee5330ff59566331052770b81f83820634dfb70770b07c45949fa97033f19c626e55041d2782edb2dc4b62a609b59f9f6735af8e4eb0f94a9a8b977f932faf53beed915ecc96d327a070aa02a42b4a2038272e0ec114b70cc34038f8fc53bfdec94176f02a8329dfee99f7b725a"
		ps384sig = "d9e2cdb9efb0836c2dde2c660f540d0f7385ce8e3dea0df943238ece28b9d91d40401cb18b8522d48473c5c16ace0af75e47f8493d98d69c08fbbf0d5d1f1274b418941cb74d18a33ea437377812b1467c369323c4fd1a7f34afa2582bd6514830566a5d7e0280bdca3fb010f308fd92dca4a6c5eeae70eabaa489d1f2b32e67a1c31db7befc9890abdddbb822faa6f2b0745ca0ec7a6913b723895d985912e3086abf2fbf55aab67e7af85842a243cb1ccb6ad10d4991831a62922282aa3f4ebce936da4ae342bd107ef8b1d6abada0b56bc09a4c70b8771a3284ca3e35ae00fcbe6b47b23630d22f586891bb15cee2070af9a38ea4534282b3b5a3c78d1ffb"
		ps512sig = "5871115b244d2d796e5ddbda20f37ceb192c3ffd02a3ffdc5d0196bc4d062c53ffcf72c4cf6cb3f25e6a10310a3e416ff8b1978cf036218d24602ba1c2c55f99282f6c3c95bebc1b4dd009ecfb629d6f922e02c3b52fc0b943673579fdbaf1f69d36e2bc8344a1c2714752078aa922d1e1fcd4408120bf09103e812f0ef28eb5abe10d9c4b270988ded9668bb59d31bd8aaacadc0a2c290c3ce90affdad70ede7beaefae4b14337b01a56365574794f243ac0598a42bcce01f48b38dbe12885c650db069858a5bd2533c6e2b1553cf9f85e348bd0eb0b15d238142acf3f60e76adf150d9b0d8ffd87e5b99fa7f496b2f8552b0a24e1e1134ff584817642093b0"
	)

	type test struct {
		name  string
		mocks func()
		kid   string
		alg   SignatureAlgorithm
		sig   string
		valid bool
		err   error
	}

	type verifyResponse struct {
		Value bool `json:"value"`
	}

	tests := []test{
		{
			name: "no get permission",
			mocks: func() {
				gock.New(host).
					Get(ecpath256).
					BodyString("").
					Reply(401).
					AddHeader("WWW-Authenticate", `Bearer authorization="https://login.windows.net/tenantID", resource="https://vault.azure.net"`)
				gock.New(host).
					Get(ecpath256).
					MatchHeader("Authorization", "Bearer "+mock.TokenBase64).
					Reply(403)
				gock.New(host).
					Post(ecpath256+"/verify").
					MatchHeader("Authorization", "Bearer "+mock.TokenBase64).
					Reply(200).
					JSON(verifyResponse{
						Value: true,
					})
			},
			kid:   host + ecpath256,
			alg:   SignatureAlgorithmES256,
			sig:   ecsig256,
			valid: true,
		},
	}

	type getResponse struct {
		Key *azkeys.JSONWebKey `json:"key"`
	}

	// ECDsa
	ecparams := []struct {
		name string
		path string
		crv  azkeys.JSONWebKeyCurveName
		alg  SignatureAlgorithm
		sig  string
	}{
		{"ec256", ecpath256, azkeys.JSONWebKeyCurveNameP256, SignatureAlgorithmES256, ecsig256},
		{"ec384", ecpath384, azkeys.JSONWebKeyCurveNameP384, SignatureAlgorithmES384, ecsig384},
		{"ec521", ecpath521, azkeys.JSONWebKeyCurveNameP521, SignatureAlgorithmES512, ecsig521},
	}

	ecmocks := func(path string, crv azkeys.JSONWebKeyCurveName) func() {
		return func() {
			gock.New(host).
				Get(path).
				BodyString("").
				Reply(401).
				AddHeader("WWW-Authenticate", `Bearer authorization="https://login.windows.net/tenantID", resource="https://vault.azure.net"`)
			gock.New(host).
				Get(path).
				MatchHeader("Authorization", "Bearer "+mock.TokenBase64).
				Reply(200).
				JSON(getResponse{
					Key: mockECKey(crv, host+path),
				})
		}
	}

	for _, param := range ecparams {
		tests = append(tests, test{
			name:  param.name,
			mocks: ecmocks(param.path, param.crv),
			kid:   host + param.path,
			alg:   param.alg,
			sig:   param.sig,
			valid: true,
		})
	}

	// RSA
	rsaparams := []struct {
		name string
		alg  SignatureAlgorithm
		sig  string
	}{
		{"ps256", SignatureAlgorithmPS256, ps256sig},
		{"ps384", SignatureAlgorithmPS384, ps384sig},
		{"ps512", SignatureAlgorithmPS512, ps512sig},
	}

	for _, param := range rsaparams {
		tests = append(tests, test{
			name: param.name,
			mocks: func() {
				gock.New(host).
					Get(rsapath).
					BodyString("").
					Reply(401).
					AddHeader("WWW-Authenticate", `Bearer authorization="https://login.windows.net/tenantID", resource="https://vault.azure.net"`)
				gock.New(host).
					Get(rsapath).
					MatchHeader("Authorization", "Bearer "+mock.TokenBase64).
					Reply(200).
					JSON(getResponse{
						Key: mockRSA(host + rsapath),
					})
			},
			kid:   host + rsapath,
			alg:   param.alg,
			sig:   param.sig,
			valid: true,
		})
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Cleanup(gock.Off)

			if tt.mocks != nil {
				tt.mocks()
			}

			client, err := NewClient(tt.kid, &mock.TokenCredential{}, mockOptions())
			require.NoError(t, err)

			sig, err := hex.DecodeString(tt.sig)
			require.NoError(t, err)

			result, err := client.VerifyData(context.Background(), tt.alg, []byte(plaintext), sig, nil)
			if tt.err != nil {
				require.ErrorIs(t, err, tt.err)
				return
			}
			require.NoError(t, err)

			require.Equal(t, tt.valid, result.Valid)
			require.True(t, gock.IsDone())
		})
	}
}

func mockOptions() *ClientOptions {
	return &ClientOptions{
		ClientOptions: azkeys.ClientOptions{
			ClientOptions: azcore.ClientOptions{
				Transport: mock.Transport,
			},
		},
	}
}

func mockECKey(crv azkeys.JSONWebKeyCurveName, kid string) *azkeys.JSONWebKey {
	// Base64 values from ephemeral keys using Azure CLI.
	// cspell:disable
	x := "7WxNBlctcTGSin66Wagm+TjuJNkakZ66/kBWbrEXH7A="
	y := "eezcbUP083FjPhwp+uTTXiJVKI7/j+IMYMl4uYrF95Y="
	switch crv {
	case azkeys.JSONWebKeyCurveNameP256:
		break
	case azkeys.JSONWebKeyCurveNameP384:
		x = "CN2bzuogXSsahPvx5fnom0KIfw5/pKfLwZh1QAoqmErcX7PKpLDu67/0VR3LvkES"
		y = "C1fJHeX5u1LDXiLO9SEsZepur+LnLFrrcqGIAXWbNx0H6rxFRZqd15QEZODt/FGg"
	case azkeys.JSONWebKeyCurveNameP521:
		x = "AORt7t7Btv00oLWtE6dTBXAWOGYv9NcpypijZ27dXZjns43Ew5FOdNveOd5HfgQinDQItvm353ddr7784Pa4eS4g"
		y = "AGNF3iJhjCK5qrrwKYus1xwraW2drP9SVWkYwSoY6LupkRwWwSq3QlK3KaDdT2b3lPLZbkLfg2mPICLDXl8WCw1D"
	default:
		panic(crv + " not supported")
	}
	// cspell:enable

	return &azkeys.JSONWebKey{
		KID: to.Ptr(azkeys.ID(kid)),
		Kty: to.Ptr(azkeys.JSONWebKeyTypeEC),
		Crv: to.Ptr(crv),
		X:   decode(x),
		Y:   decode(y),
	}
}

func mockRSA(kid string) *azkeys.JSONWebKey {
	// Base64 value from ephemeral key using Azure CLI.
	n := "7w8lfvEJnlky5LwmiBiZ7TEmOOCqUfrdlwxyiTQ/usAaldoEDf1vltIZGOGkUZa1pzElBBqXuVlzZJ2BridEKhASYwguCtM8ByQdpyQ4BnFQgPMAqqTTi2xb441y/h6sLUuCtXevNuYUI4yoVS4MeZFKAF0JVHhaeeHh47kckJimyGjaRMsQg0ONL1r047uPFZuzGSHJ5Eh0sQebTyvjciE31GjCqa5FKgEhl7c+mFEo2zt0n9qZAq8o2F8x7nf7ksOq1k684P+XHQptJIp/0MW/P23vh/5+Z/AfiCjBAR1e0Nq4YEY42f/NYzXsjQfSsOdSuFVpW5z2BsM4WIxdWQ=="
	e := "AQAB"

	return &azkeys.JSONWebKey{
		KID: to.Ptr(azkeys.ID(kid)),
		Kty: to.Ptr(azkeys.JSONWebKeyTypeRSA),
		N:   decode(n),
		E:   decode(e),
	}
}

func decode(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
