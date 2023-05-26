// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

// cspell:ignore joho godotenv

package internal

import (
	"flag"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/joho/godotenv"
)

// Make sure these flags for testing are imported in every package containing tests.
var (
	RemoteOnly = flag.Bool("remote", false, "remote operations only; do not download key")

	envFile = flag.String("env", "", "path to .env file to load")
	live    = flag.Bool("live", false, "run live tests; use `azd up` to provision")

	loader sync.Once
)

func Live(t *testing.T) {
	t.Helper()

	if !*live {
		t.Skip("skipping live tests")
	}

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
	_ = godotenv.Load()
	return nil
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
