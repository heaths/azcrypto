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

## License

Licensed under the [MIT](LICENSE.txt) license.

[azidentity]: https://pkg.go.dev/github.com/Azure/azure-sdk-for-go/sdk/azidentity
[azkeys]: https://github.com/Azure/azure-sdk-for-go/tree/main/sdk/keyvault/azkeys
[CryptographyClient]: https://learn.microsoft.com/dotnet/api/azure.security.keyvault.keys.cryptography.cryptographyclient
