// Copyright 2023 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

package test

import (
	"net/http"
)

type testTransport struct {
	transport http.RoundTripper
}

func (t *testTransport) Do(req *http.Request) (*http.Response, error) {
	return t.transport.RoundTrip(req)
}
