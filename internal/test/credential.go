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
	Token       = "mock"
	TokenBase64 = "bW9jaw=="
)

type TokenCredential struct{}

func (c *TokenCredential) GetToken(ctx context.Context, options policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{
		Token:     TokenBase64,
		ExpiresOn: time.Now().Add(2 * time.Hour),
	}, nil
}
