// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

// Copied from https://github.com/Azure/azure-sdk-for-go/blob/1faa82f32a87a2e49bc5336beb1e4c14aa97c4b7/sdk/keyvault/internal/parse_test.go
package internal

import (
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/stretchr/testify/require"
)

func TestParseID(t *testing.T) {
	examples := map[string]struct{ url, name, version *string }{
		"https://myvaultname.vault.azure.net/keys/key1053998307/b86c2e6ad9054f4abf69cc185b99aa60":      {to.Ptr("https://myvaultname.vault.azure.net"), to.Ptr("key1053998307"), to.Ptr("b86c2e6ad9054f4abf69cc185b99aa60")},
		"https://myvaultname.vault.azure.net:8080/keys/key1053998307/b86c2e6ad9054f4abf69cc185b99aa60": {to.Ptr("https://myvaultname.vault.azure.net:8080"), to.Ptr("key1053998307"), to.Ptr("b86c2e6ad9054f4abf69cc185b99aa60")},
		"https://myvaultname.vault.azure.net/keys/key1053998307":                                       {to.Ptr("https://myvaultname.vault.azure.net"), to.Ptr("key1053998307"), nil},
		"https://myvaultname.vault.azure.net:8080/keys/key1053998307":                                  {to.Ptr("https://myvaultname.vault.azure.net:8080"), to.Ptr("key1053998307"), nil},
		"https://myvaultname.vault.azure.net/":                                                         {to.Ptr("https://myvaultname.vault.azure.net"), nil, nil},
		"https://myvaultname.vault.azure.net:8080":                                                     {to.Ptr("https://myvaultname.vault.azure.net:8080"), nil, nil},
	}

	for url, expected := range examples {
		url, name, version := ParseID(&url)
		if expected.url == nil {
			require.Nil(t, url)
		} else {
			require.NotNil(t, url)
			require.Equal(t, *expected.url, *url)
		}
		if expected.name == nil {
			require.Nil(t, name)
		} else {
			require.NotNilf(t, name, "expected %s", *expected.name)
			require.Equal(t, *expected.name, *name)
		}
		if expected.version == nil {
			require.Nil(t, version)
		} else {
			require.NotNil(t, version)
			require.Equal(t, *expected.version, *version)
		}
	}
}
