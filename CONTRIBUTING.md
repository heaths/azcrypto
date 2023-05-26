# Contributing

Contributions are welcome! To get started quickly, you can open this project in a [devcontainer] which should have the prerequisites already installed;
otherwise, please installed the required software below.

## Prerequisites

* [Go] 1.18 or newer.
* (Recommended) [azd] 0.9.0 or newer.

## Build

To build the module, run the following in the repository root directory:

```bash
go build
```

### Samples

To build and run sample applications under _./cmd_ e.g., _./cmd/sign_, specify the subdirectory and any command line arguments required:

```bash
go run ./cmd/sign {keyID} {plaintext}
```

## Test

To run all tests for the module, run the following in the repository root directory:

```bash
go test ./...
```

### Live

To provision resources and run live tests, you can use [azd] and run the following in the repository root directory:

```bash
azd up # or `azd provision` to just provision resources
go test ./... -args -live # (-env=<file>) (-remote)
```

By default, the live tests will load any _.env_ file `azd` created, falling back to any _.env_ file you have in the repository root
as well as any environment variables already set. You can override this behavior by passing a the path to an environment file to
`-env`.

To run tests only against the Azure Key Vault or Managed HSM without trying to download the key, pass `-remote`.

When you are finished with these resources, you can delete the resource group and all resources within it:

```bash
azd down
```

#### Authentication

Running `azd` will prompt you to first log in; however, if you are running in a [devcontainer],
you may need to use a device code and follow the prompts:

```bash
azd auth login --use-device-code
```

[azd]: https://aka.ms/azd
[Go]: https://go.dev
[devcontainer]: https://code.visualstudio.com/docs/devcontainers/containers
