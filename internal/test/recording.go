// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

// cspell:ignore dnaeon,godotenv,joho,traceparent

package test

import (
	"flag"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/joho/godotenv"
	"golang.org/x/exp/slices"
	"gopkg.in/dnaeon/go-vcr.v3/cassette"
	"gopkg.in/dnaeon/go-vcr.v3/recorder"
)

const (
	sanitizedValue = "sanitized"
)

// Make sure these flags for testing are imported in every package containing tests.
var (
	RemoteOnly = flag.Bool("remote", false, "remote operations only; do not download key")
	envFile    = flag.String("env", "", "path to .env file to load")
	live       = flag.Bool("live", false, "run live tests; use `azd up` to provision")

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
		"traceparent",
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

type Recording struct {
	passthrough bool
	transport   policy.Transporter
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
	r.recorder.AddHook(func(i *cassette.Interaction) error {
		req, err := i.GetHTTPRequest()
		if err != nil {
			panic(err)
		}
		resp, err := i.GetHTTPResponse()
		if err != nil {
			panic(err)
		}
		code, body := override(req, resp)
		if code != 0 {
			i.Response.Code = code
			i.Response.Status = http.StatusText(code)
			i.Response.Body = body
			i.Response.ContentLength = int64(len(body))
		}
		return nil
	}, recorder.AfterCaptureHook)
}

type ClientFactory[T any] func(*Recording) (*T, error)

func Recorded[T any](t *testing.T, factory ClientFactory[T]) *T {
	t.Helper()

	mode := recorder.ModeRecordOnce
	if *live {
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

	passthrough := *live || r.IsRecording()
	if passthrough {
		initEnv(t)
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

func initEnv(t *testing.T) {
	t.Helper()

	required := map[string]string{
		"AZURE_KEYVAULT_URL": os.Getenv("AZURE_KEYVAULT_URL"),
	}
	for k, v := range required {
		if v == "" {
			loader.Do(func() {
				if err := loadEnv(); err != nil {
					t.Fatal(err)
				}
			})
		}

		v = os.Getenv(k)
		if v == "" {
			t.Fatalf("environment variable %s must be defined for live tests", k)
		}
	}
}

func loadEnv() error {
	// Use only the specified .env file.
	if *envFile != "" {
		return godotenv.Load(*envFile)
	}

	// Load any .env files from azd.
	files, err := fs.Glob(os.DirFS(".azure"), "**/.env")
	if err != nil {
		return err
	}

	if len(files) > 1 {
		return fmt.Errorf("multiple .azure/**/.env files found; pass -env=<path> to specify")
	} else if len(files) == 1 {
		path := filepath.Join(".azure", files[0])
		if err = godotenv.Load(path); err != nil {
			return err
		}
	}

	// Fall back to root .env for additional vars.
	_, err = os.Stat(".env")
	if os.IsNotExist(err) {
		return nil
	}

	return godotenv.Load()
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
