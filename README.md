# Cryptography Client for Azure Key Vault

[![reference](https://pkg.go.dev/badge/github.com/heaths/azcrypto.svg)](https://pkg.go.dev/github.com/heaths/azcrypto)
[![ci](https://github.com/heaths/azcrypto/actions/workflows/ci.yml/badge.svg?event=push)](https://github.com/heaths/azcrypto/actions/workflows/ci.yml)

This module provides a cryptography client for the [Azure Key Vault Keys client module for Go][azkeys].
This project is **not** supported by the Azure SDK team, but does align with the cryptography clients in other supported languages like the [CryptographyClient] I wrote for the Azure SDK for .NET.

## Getting started

### Install packages

Install `azcrypto` and `azidentity` with `go get`:

```bash
go get github.com/heaths/azcrypto
go get github.com/Azure/azure-sdk-for-go/sdk/azidentity
```

[azidentity] is used for Azure Active Directory authentication as demonstrated below.

### Prerequisites

* An [Azure subscription](https://azure.microsoft.com/free/).
* An Azure key vault or managed HSM. If you need to create one, see the Key Vault documentation for instructions using the [Azure Portal](https://docs.microsoft.com/azure/key-vault/general/quick-create-portal) or the [Azure CLI](https://docs.microsoft.com/azure/key-vault/general/quick-create-cli).

### Authentication

This document demonstrates using [azidentity.NewDefaultAzureCredential] to authenticate. This credential type works in both local development and production environments. We recommend using a [managed identity] in production.

`NewClient` accepts any [azcore.TokenCredential] including those from [azidentity]. See the [azidentity] documentation for more information about other credential types.

#### Create a client

Constructing the client requires your key's URL, called a key ID, which you can get from the Azure Portal or Azure CLI. You should store this key ID including the version used to encrypt, sign, or wrap with your data to make sure you can decrypt, verify, and unwrap.

```go
import (
    "github.com/Azure/azure-sdk-for-go/sdk/azidentity"
    "github.com/heaths/azcrypto"
)

func main() {
    cred, err := azidentity.NewDefaultAzureCredential(nil)
    if err != nil {
        // TODO: handle error
    }

    client, err := azcrypto.NewClient(
        "https://{vault-name}.vault.azure.net/keys/{key-name}/{key-version}",
        cred,
        nil,
    )
    if err != nil {
        // TODO: handle error
    }
}
```

## Key concepts

The `Client` will attempt to download the specified public key when first used. This will improve throughput while reducing the risk of getting throttled by Key Vault's [rate limits].

### Sign and verify

Because signing requires a private key and Azure Key Vault or Managed HSM does not provide access, by default, to the private key, the following signing operation will be performed remotely while the verifying operation will be performed locally, assuming the caller has the `keys/get` data action permission.

```go
import (
    "context"
    "crypto/sha256"

    "github.com/heaths/azcrypto"
)

func signAndVerify(client *azcrypto.Client, plaintext string) (bool, error) {
    // Performed remotely by Azure Key Vault or Managed HSM.
    signResult, err := client.SignData(
        context.TODO(),
        azcrypto.SignatureAlgorithmES256,
        []byte(plaintext),
        nil,
    )
    if err != nil {
        return false, err
    }

    // Performed locally if the public key could be retrieved.
    verifyResult, err := client.VerifyData(
        context.TODO(),
        signResult.Algorithm,
        []byte(plaintext),
        signResult.Signature,
        nil,
    )
    if err != nil {
        return false, err
    }

    return verifyResult.Valid, nil
}
```

## Examples

Get started with our [examples].

## License

Licensed under the [MIT](LICENSE.txt) license.

[azcore.TokenCredential]: https://pkg.go.dev/github.com/Azure/azure-sdk-for-go/sdk/azcore#TokenCredential
[azidentity.NewDefaultAzureCredential]: https://pkg.go.dev/github.com/Azure/azure-sdk-for-go/sdk/azidentity#NewDefaultAzureCredential
[azidentity]: https://pkg.go.dev/github.com/Azure/azure-sdk-for-go/sdk/azidentity
[azkeys]: https://pkg.go.dev/github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys
[CryptographyClient]: https://learn.microsoft.com/dotnet/api/azure.security.keyvault.keys.cryptography.cryptographyclient
[examples]: https://pkg.go.dev/github.com/heaths/azcrypto#pkg-examples
[managed identity]: https://docs.microsoft.com/azure/active-directory/managed-identities-azure-resources/overview
[rate limits]: https://learn.microsoft.com/azure/key-vault/general/service-limits
