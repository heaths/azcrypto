// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

// cspell:ignore dnaeon

package test

import (
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"golang.org/x/exp/slices"
	"gopkg.in/dnaeon/go-vcr.v3/cassette"
	"gopkg.in/dnaeon/go-vcr.v3/recorder"
)

const (
	sanitizedValue = "sanitized"
)

// Make sure these flags for testing are imported in every package containing tests.
var (
	remoteFlag = flag.Bool("remote", false, "remote operations only; do not download key")
	liveFlag   = flag.Bool("live", false, `run live tests; use "azd up" to provision`)

	loader sync.Once

	safeHeaders = []string{
		"accept",
		"cache-control",
		"content-length",
		"content-type",
		"date",
		"expires",
		"pragma",
		"retry-after",
		"server",
		"strict-transport-security",
		"user-agent",
		"www-authenticate",
		"x-content-type-options",
		"x-ms-client-request-id",
		"x-ms-keyvault-network-info",
		"x-ms-keyvault-region",
		"x-ms-keyvault-service-version",
		"x-ms-request-id",
		"x-ms-return-client-request-id",
	}
)

func IsRemoteOnly() bool {
	return *remoteFlag
}

type Recording struct {
	passthrough bool
	transport   *testTransport
	credential  azcore.TokenCredential
	recorder    *recorder.Recorder
}

func (r *Recording) IsPassthrough() bool {
	return r.passthrough
}

func (r *Recording) GetTransport() policy.Transporter {
	return r.transport
}

func (r *Recording) GetCredential() azcore.TokenCredential {
	return r.credential
}

type RecordingOverride func(req *http.Request, resp *http.Response) (code int, body string)

func (r *Recording) OverrideResponse(override RecordingOverride) {
	// Override response in testTransport since any recorder.HookFunc is bypassed in ModePassthrough.
	r.transport.addOverride(override)
}

type ClientFactory[T any] func(*Recording) (*T, error)

func Recorded[T any](t *testing.T, factory ClientFactory[T]) *T {
	t.Helper()

	mode := recorder.ModeRecordOnce
	if *liveFlag {
		mode = recorder.ModePassthrough
	}
	r, err := recorder.NewWithOptions(&recorder.Options{
		CassetteName:       "fixtures/" + t.Name(),
		Mode:               mode,
		RealTransport:      http.DefaultTransport,
		SkipRequestLatency: true,
	})
	if err != nil {
		t.Fatal("new recorder:", err)
	}
	t.Cleanup(func() {
		err := r.Stop()
		if err != nil {
			t.Fatal("stop recorder:", err)
		}
	})

	passthrough := *liveFlag || r.IsRecording()
	if passthrough {
		loadVariables(t)
	}

	sanitize := func(headers http.Header) {
		for name := range headers {
			lower := strings.ToLower(name)
			if !slices.Contains(safeHeaders, lower) {
				headers[name] = []string{sanitizedValue}
			}
		}
	}
	r.AddHook(func(i *cassette.Interaction) error {
		sanitize(i.Request.Headers)
		sanitize(i.Response.Headers)
		return nil
	}, recorder.BeforeSaveHook)

	r.SetMatcher(func(r *http.Request, i cassette.Request) bool {
		uri, err := url.ParseRequestURI(i.URL)
		if err != nil {
			t.Fatal("parse interaction:", err)
		}
		// Always ignore the host in playback.
		return r.Method == i.Method && r.URL.EscapedPath() == uri.EscapedPath()
	})

	r.AddPassthrough(func(req *http.Request) bool {
		vaultURL := os.Getenv("AZURE_KEYVAULT_URL")
		return vaultURL != "" && !strings.HasPrefix(req.URL.String(), vaultURL)
	})

	transport := &testTransport{
		transport: r.GetDefaultClient().Transport,
	}
	dac, err := azidentity.NewDefaultAzureCredential(&azidentity.DefaultAzureCredentialOptions{
		ClientOptions: azcore.ClientOptions{
			Transport: transport,
		},
	})
	if err != nil {
		t.Fatal("NewDefaultAzureCredential:", err)
	}

	credential := &testCredential{
		credential:  dac,
		passthrough: passthrough,
	}

	recording := Recording{
		passthrough: passthrough,
		transport:   transport,
		credential:  credential,
		recorder:    r,
	}

	client, err := factory(&recording)
	if err != nil {
		t.Fatal("new client:", err)
	}

	return client
}

func URLJoinPath(base string, elem ...string) (string, error) {
	// TODO: Use url.JoinPath after upgrading to Go 1.19 or newer.
	if base == "" {
		return "", fmt.Errorf("base required")
	}

	url, err := url.Parse(base)
	if err != nil {
		return "", err
	}

	res := make([]string, 0, len(elem)+1)
	res = append(res, strings.TrimSuffix(url.String(), "/"))

	for _, s := range elem {
		res = append(res, strings.Trim(s, "/"))
	}

	return strings.Join(res, "/"), nil
}
