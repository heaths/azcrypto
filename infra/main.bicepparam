using './main.bicep'

param environmentName = readEnvironmentVariable('AZURE_ENV_NAME', '')
param location = readEnvironmentVariable('AZURE_LOCATION', '')
param principalId = readEnvironmentVariable('AZURE_PRINCIPAL_ID', '')
param vaultName = readEnvironmentVariable('AZURE_KEYVAULT_NAME', '')
param managedHsm = bool(readEnvironmentVariable('AZURE_MANAGEDHSM', 'false'))
