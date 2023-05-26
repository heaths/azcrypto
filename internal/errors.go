// Copyright 2023 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

package internal

import (
	"errors"

	_ "github.com/heaths/azcrypto/internal/test"
)

var (
	ErrUnsupported = errors.New("operation not supported")
)
