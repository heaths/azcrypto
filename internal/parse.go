// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

// Copied from https://github.com/Azure/azure-sdk-for-go/blob/1faa82f32a87a2e49bc5336beb1e4c14aa97c4b7/sdk/keyvault/internal/parse.go
package internal

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
)

// ParseID parses "https://myvaultname.vault.azure.net/keys/key1053998307/b86c2e6ad9054f4abf69cc185b99aa60"
// into "https://myvaultname.managedhsm.azure.net/", "key1053998307", and "b86c2e6ad9054f4abf69cc185b99aa60"
func ParseID(id *string) (*string, *string, *string) {
	if id == nil {
		return nil, nil, nil
	}
	parsed, err := url.Parse(*id)
	if err != nil {
		return nil, nil, nil
	}

	url := fmt.Sprintf("%s://%s", parsed.Scheme, parsed.Host)
	split := strings.Split(strings.TrimPrefix(parsed.Path, "/"), "/")
	if len(split) < 3 {
		if len(split) == 2 {
			return &url, to.Ptr(split[1]), nil
		}
		return &url, nil, nil
	}

	return &url, to.Ptr(split[1]), to.Ptr(split[2])
}
