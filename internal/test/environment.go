// Copyright 2023 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

// cspell:ignore azdcontext,godotenv,joho

package test

import (
	"flag"
	"os"
	"testing"

	"github.com/azure/azure-dev/cli/azd/pkg/environment/azdcontext"
	"github.com/joho/godotenv"
)

var (
	envFlag = flag.String("env", "", "name of a specific azd environment to load")
)

func loadVariables(t *testing.T) {
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
	context, err := azdcontext.NewAzdContext()
	if err == azdcontext.ErrNoProject {
		return nil
	} else if err != nil {
		return err
	}

	name := *envFlag
	if name == "" {
		if name, err = context.GetDefaultEnvironmentName(); err != nil {
			return err
		}
	}

	path := context.EnvironmentDotEnvPath(name)
	if err = godotenv.Load(path); err != nil && os.IsNotExist(err) {
		return nil
	}

	return err
}
