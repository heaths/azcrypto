// Copyright 2023 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

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

func TestClient_SignData(t *testing.T) {
	// cspell:disable
	const (
		host = "https://test.vault.azure.net"

		path256         = "/keys/ec256/d66bce8f4df64a9a9e172239d9f62572"
		kid256          = host + path256
		sig256base64url = "bx69NxzK4aRVu3CcW7LD6Znt5-00uOXj05lFCPI4wzxI-XnJhhgva4970_snfMOmwQ9C7pBtGEINbueJVyD8qA"
		sig256          = "6f1ebd371ccae1a455bb709c5bb2c3e999ede7ed34b8e5e3d3994508f238c33c48f979c986182f6b8f7bd3fb277cc3a6c10f42ee906d18420d6ee7895720fca8"

		path384         = "/keys/ec384/7e82704e15b049d1b5f3e9953ad5403c"
		kid384          = host + path384
		sig384base64url = "Eb6cSdVc_qmfnSKx_a7WfLvaKLBFje5Y-4FsO0K2oBujHLM7a246L-CkaXAd85vJrJMmKoiL8BSaUGVfOBdhUYGM2WKoLfcOzrxhLTGmqaJgQ_SVpwzqor9g_1X76aD9"
		sig384          = "11be9c49d55cfea99f9d22b1fdaed67cbbda28b0458dee58fb816c3b42b6a01ba31cb33b6b6e3a2fe0a469701df39bc9ac93262a888bf0149a50655f38176151818cd962a82df70ecebc612d31a6a9a26043f495a70ceaa2bf60ff55fbe9a0fd"

		path521         = "/keys/ec521/781a62b96fea441095edf3a115c94c5f"
		kid521          = host + path521
		sig521base64url = "AaZsoVz1dt-1wYiQ1VwIpD_08puGyvRII5tW0JumWLa8g87pJlWYJXihb10t_UAT-_ECEBncj82CVoRTeSjptMpWAb9F8mXKSuk_iJyDuOBIcKtFlfk1d7sgEDMxtoB34inrPXGg6eqvSgJ3k3xbPL29U54fIa82C6wwvtNopSpp5QTr"
		sig521          = "01a66ca15cf576dfb5c18890d55c08a43ff4f29b86caf448239b56d09ba658b6bc83cee92655982578a16f5d2dfd4013fbf1021019dc8fcd825684537928e9b4ca5601bf45f265ca4ae93f889c83b8e04870ab4595f93577bb20103331b68077e229eb3d71a0e9eaaf4a0277937c5b3cbdbd539e1f21af360bac30bed368a52a69e504eb"

		plaintext = "message"
	)
	// cspell:enable

	tests := []struct {
		name  string
		mocks func()
		kid   string
		alg   SignatureAlgorithm
		sig   string
		err   error
	}{
		{
			name: "es256",
			mocks: func() {
				gock.New(host).
					Post(path256).
					BodyString("").
					Reply(401).
					AddHeader("WWW-Authenticate", `Bearer authorization="https://login.windows.net/tenantID", resource="https://vault.azure.net"`)
				gock.New(host).
					Post(path256).
					MatchHeader("Authorization", "Bearer "+mock.TokenBase64).
					Reply(200).
					JSON(signResponse{
						KID:   kid256,
						Value: sig256base64url,
					})
			},
			kid: kid256,
			sig: sig256,
		},
		{
			name: "es384",
			mocks: func() {
				gock.New(host).
					Post(path384).
					BodyString("").
					Reply(401).
					AddHeader("WWW-Authenticate", `Bearer authorization="https://login.windows.net/tenantID", resource="https://vault.azure.net"`)
				gock.New(host).
					Post(path384).
					MatchHeader("Authorization", "Bearer "+mock.TokenBase64).
					Reply(200).
					JSON(signResponse{
						KID:   kid384,
						Value: sig384base64url,
					})
			},
			kid: kid384,
			sig: sig384,
		},
		{
			name: "es521",
			mocks: func() {
				gock.New(host).
					Post(path521).
					BodyString("").
					Reply(401).
					AddHeader("WWW-Authenticate", `Bearer authorization="https://login.windows.net/tenantID", resource="https://vault.azure.net"`)
				gock.New(host).
					Post(path521).
					MatchHeader("Authorization", "Bearer "+mock.TokenBase64).
					Reply(200).
					JSON(signResponse{
						KID:   kid521,
						Value: sig521base64url,
					})
			},
			kid: kid521,
			sig: sig521,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Cleanup(gock.Off)

			if tt.mocks != nil {
				tt.mocks()
			}

			client, err := NewClient(tt.kid, &mock.TokenCredential{}, mockOptions())
			require.NoError(t, err)

			result, err := client.SignData(context.Background(), SignatureAlgorithmES256, []byte("test"), nil)
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
	// cspell:disable
	const (
		host = "https://test.vault.azure.net"

		path256 = "/keys/ec256/d66bce8f4df64a9a9e172239d9f62572"
		kid256  = host + path256

		path384 = "/keys/ec384/7e82704e15b049d1b5f3e9953ad5403c"
		kid384  = host + path384

		path521 = "/keys/ec521/781a62b96fea441095edf3a115c94c5f"
		kid521  = host + path521

		plaintext = "message"
		sig256    = "6f1ebd371ccae1a455bb709c5bb2c3e999ede7ed34b8e5e3d3994508f238c33c48f979c986182f6b8f7bd3fb277cc3a6c10f42ee906d18420d6ee7895720fca8"
		sig384    = "11be9c49d55cfea99f9d22b1fdaed67cbbda28b0458dee58fb816c3b42b6a01ba31cb33b6b6e3a2fe0a469701df39bc9ac93262a888bf0149a50655f38176151818cd962a82df70ecebc612d31a6a9a26043f495a70ceaa2bf60ff55fbe9a0fd"
		sig521    = "01a66ca15cf576dfb5c18890d55c08a43ff4f29b86caf448239b56d09ba658b6bc83cee92655982578a16f5d2dfd4013fbf1021019dc8fcd825684537928e9b4ca5601bf45f265ca4ae93f889c83b8e04870ab4595f93577bb20103331b68077e229eb3d71a0e9eaaf4a0277937c5b3cbdbd539e1f21af360bac30bed368a52a69e504eb"
	)
	// cspell:enable

	tests := []struct {
		name  string
		mocks func()
		kid   string
		alg   SignatureAlgorithm
		sig   string
		valid bool
		err   error
	}{
		{
			name: "es256",
			mocks: func() {
				gock.New(host).
					Get(path256).
					BodyString("").
					Reply(401).
					AddHeader("WWW-Authenticate", `Bearer authorization="https://login.windows.net/tenantID", resource="https://vault.azure.net"`)
				gock.New(host).
					Get(path256).
					MatchHeader("Authorization", "Bearer "+mock.TokenBase64).
					Reply(200).
					JSON(getResponse{
						Key: mockECKey(azkeys.JSONWebKeyCurveNameP256, kid256),
					})
			},
			kid:   kid256,
			alg:   SignatureAlgorithmES256,
			sig:   sig256,
			valid: true,
		},
		{
			name: "es356",
			mocks: func() {
				gock.New(host).
					Get(path384).
					BodyString("").
					Reply(401).
					AddHeader("WWW-Authenticate", `Bearer authorization="https://login.windows.net/tenantID", resource="https://vault.azure.net"`)
				gock.New(host).
					Get(path384).
					MatchHeader("Authorization", "Bearer "+mock.TokenBase64).
					Reply(200).
					JSON(getResponse{
						Key: mockECKey(azkeys.JSONWebKeyCurveNameP384, kid384),
					})
			},
			kid:   kid384,
			alg:   SignatureAlgorithmES384,
			sig:   sig384,
			valid: true,
		},
		{
			name: "es521",
			mocks: func() {
				gock.New(host).
					Get(path521).
					BodyString("").
					Reply(401).
					AddHeader("WWW-Authenticate", `Bearer authorization="https://login.windows.net/tenantID", resource="https://vault.azure.net"`)
				gock.New(host).
					Get(path521).
					MatchHeader("Authorization", "Bearer "+mock.TokenBase64).
					Reply(200).
					JSON(getResponse{
						Key: mockECKey(azkeys.JSONWebKeyCurveNameP521, kid521),
					})
			},
			kid:   kid521,
			alg:   SignatureAlgorithmES512,
			sig:   sig521,
			valid: true,
		},
		{
			name: "no get permission",
			mocks: func() {
				gock.New(host).
					Get(path256).
					BodyString("").
					Reply(401).
					AddHeader("WWW-Authenticate", `Bearer authorization="https://login.windows.net/tenantID", resource="https://vault.azure.net"`)
				gock.New(host).
					Get(path256).
					MatchHeader("Authorization", "Bearer "+mock.TokenBase64).
					Reply(403)
				gock.New(host).
					Post(path256+"/verify").
					MatchHeader("Authorization", "Bearer "+mock.TokenBase64).
					Reply(200).
					JSON(verifyResponse{
						Value: true,
					})
			},
			kid:   kid256,
			alg:   SignatureAlgorithmES256,
			sig:   sig256,
			valid: true,
		},
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

type getResponse struct {
	Key *azkeys.JSONWebKey `json:"key"`
}

type signResponse struct {
	KID   string `json:"kid"`
	Value string `json:"value"`
}

type verifyResponse struct {
	Value bool `json:"value"`
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

	decode := func(s string) []byte {
		b, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			panic(err)
		}
		return b
	}

	return &azkeys.JSONWebKey{
		KID: to.Ptr(azkeys.ID(kid)),
		Kty: to.Ptr(azkeys.JSONWebKeyTypeEC),
		Crv: to.Ptr(crv),
		X:   decode(x),
		Y:   decode(y),
	}
}
