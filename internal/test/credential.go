// Copyright 2023 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

package test

import (
	"context"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
)

const (
	token       = "mock"
	tokenBase64 = "bW9jaw=="
)

var MockCredential azcore.TokenCredential = &testCredential{}

type testCredential struct {
	credential  azcore.TokenCredential
	passthrough bool
}

func (c *testCredential) GetToken(ctx context.Context, options policy.TokenRequestOptions) (azcore.AccessToken, error) {
	if c.passthrough {
		return c.credential.GetToken(ctx, options)
	}

	return azcore.AccessToken{
		Token:     tokenBase64,
		ExpiresOn: time.Now().Add(2 * time.Hour),
	}, nil
}
