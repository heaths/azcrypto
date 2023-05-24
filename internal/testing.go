// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

// cspell:ignore joho godotenv

package internal

import (
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/joho/godotenv"
)

// Make sure these flags for testing are imported in every package containing tests.
var (
	RemoteOnly = flag.Bool("remote", false, "remote operations only; do not download key")

	envFile = flag.String("env", "", "path to .env file to load")
	live    = flag.Bool("live", false, "run live tests; use `azd up` to provision")
)

func RequireLive(t *testing.T) {
	if !*live {
		t.Skip("skipping live tests")
	}
}

func LoadEnv() error {
	// Use specified .env file only.
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
