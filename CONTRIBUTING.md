# Contributing

Contributions are welcome! To get started quickly, you can open this project in a [devcontainer] which should have the prerequisites already installed;
otherwise, please installed the required software below.

## Prerequisites

* [Go] 1.18 or newer.
* (Recommended) [Azure CLI][az] 2.49.0 or newer.
* (Recommended) [Azure Developer CLI][azd] 1.0.1 or newer.

## Build

To build the module, run the following in the repository root directory:

```bash
go build
```

## Test

To run all tests for the module, run the following in the repository root directory:

```bash
go test ./...
```

If recorded tests were added or modified, you'll need to provision live resources.

### Live

To provision resources, and run or record live tests, you can use [azd] and run the following in the repository root directory:

```bash
azd up
go test ./... # -args (-env=<name>) (-live) (-remote)
```

Live and recording tests will load the default [azd] environment's _.env_ as environment variables.
You can pass a specific environment name to `-env` to use a different environment.

If any recorded tests were added, they will be recorded automatically with no additional arguments.
To run tests without reading or updating recordings, pass `-live`.

To run tests only against the Azure Key Vault or Managed HSM without trying to download the key, pass `-remote`.

When you are finished with these resources, you can delete the resource group and all resources within it:

```bash
azd down
```

#### Authentication

To run live tests, you first need to authenticate [az]:

```bash
az login
```

To provision live test resources, you also need to authenticate [azd]. Normally, it will prompt you to log in
the first time it is run; however, if you are running in a [devcontainer] you may need to use a device code:

```bash
azd auth login --use-device-code
```

#### Environments

You can run live tests against either Azure [Key Vault] or [Managed HSM]. A Key Vault and keys needed for testing will
be provisioned by default considering [pricing], so if you merely run `az up` you will be prompted for a couple of
parameters and then a Key Vault is provisioned; however, you can pre-create environments to easily switch between the two.

##### Key Vault

To pre-create, provision, and test an environment for Azure [Key Vault], substituting "keyvault" with any name you'd prefer:

```bash
azd env new keyvault # --location {location} --subscription {subscription}
azd up -e keyvault
go test ./... -args -env keyvault -live
```

##### Managed HSM

To pre-create, provision, and test an environment for Azure [Managed HSM], substituting "managedhsm" with any name you'd prefer:

```bash
azd env new managedhsm # --location {location} --subscription {subscription}
azd env set -e managedhsm AZURE_MANAGEDHSM true
azd up -e managedhsm
go test ./... -args -env managedhsm -live
```

[az]: https://aka.ms/azcli
[azd]: https://aka.ms/azd
[Go]: https://go.dev
[devcontainer]: https://code.visualstudio.com/docs/devcontainers/containers
[Key Vault]: https://learn.microsoft.com/azure/key-vault/general/
[Managed HSM]: https://learn.microsoft.com/azure/key-vault/managed-hsm/
[pricing]: https://azure.microsoft.com/pricing/details/key-vault/
