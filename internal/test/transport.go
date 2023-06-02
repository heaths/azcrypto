// Copyright 2023 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

package test

import (
	"bytes"
	"io"
	"net/http"
)

type testTransport struct {
	transport http.RoundTripper
	overrides []RecordingOverride
}

func (t *testTransport) Do(req *http.Request) (*http.Response, error) {
	resp, err := t.transport.RoundTrip(req)
	if err != nil {
		return resp, err
	}

	for _, override := range t.overrides {
		code, body := override(req, resp)
		if code != 0 {
			resp.StatusCode = code
			resp.Status = http.StatusText(code)
			resp.Body = io.NopCloser(bytes.NewBufferString(body))
			resp.ContentLength = int64(len(body))
		}
	}

	return resp, nil
}

func (t *testTransport) addOverride(override RecordingOverride) {
	t.overrides = append(t.overrides, override)
}
