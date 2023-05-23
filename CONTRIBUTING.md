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

### Provisioning live resources

To provision live resources for testing, you can use [azd] and run the following in the repository root directory:

```bash
azd up # or `azd provision` to just provision resources
```

When you are finished, you can delete the resource group and all resources within it:

```bash
azd down
```

[azd]: https://aka.ms/azd
[Go]: https://go.dev
[devcontainer]: https://code.visualstudio.com/docs/devcontainers/containers
