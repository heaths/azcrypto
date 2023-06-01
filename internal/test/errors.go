// Copyright 2023 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

package test

import (
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/stretchr/testify/require"
)

func RequireIfResponseError(t *testing.T, err error, target error) bool {
	if err, ok := err.(*azcore.ResponseError); ok {
		if target, ok := target.(*azcore.ResponseError); ok {
			require.Equal(t, target.StatusCode, err.StatusCode)
			return true
		}
	}
	return false
}
