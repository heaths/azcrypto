// Copyright 2023 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

package mock

import (
	"net/http"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
)

// Transport wraps the http.DefaultTransport for use with gock.
var Transport policy.Transporter = &mockTransport{}

type mockTransport struct{}

func (t *mockTransport) Do(req *http.Request) (*http.Response, error) {
	// gock will automatically intercept the http.DefaultTransport.
	return http.DefaultTransport.RoundTrip(req)
}
