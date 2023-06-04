// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

package test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestURLJoinPath(t *testing.T) {
	t.Parallel()

	const want = "https://test.vault.azure.net/keys/key-name/key-version"
	tests := []struct {
		base    string
		elems   []string
		wantErr bool
	}{
		{
			base:    "",
			wantErr: true,
		},
		{
			base:  "https://test.vault.azure.net",
			elems: []string{"keys/key-name/key-version"},
		},
		{
			base:  "https://test.vault.azure.net",
			elems: []string{"/keys/key-name/key-version"},
		},
		{
			base:  "https://test.vault.azure.net/",
			elems: []string{"keys/key-name/key-version"},
		},
		{
			base:  "https://test.vault.azure.net",
			elems: []string{"keys", "key-name", "key-version"},
		},
		{
			base:  "https://test.vault.azure.net/",
			elems: []string{"keys", "key-name", "key-version"},
		},
	}

	for i, tt := range tests {
		t.Run(fmt.Sprintf("tests_%d", i), func(t *testing.T) {
			got, err := URLJoinPath(tt.base, tt.elems...)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.Equal(t, want, got)
		})
	}
}
