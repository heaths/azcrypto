using './main.bicep'

// cspell:ignore azcryptokv,eastus2
param environmentName = readEnvironmentVariable('AZURE_ENV_NAME', 'azcryptokv')
param location = readEnvironmentVariable('AZURE_LOCATION', 'eastus2')
param principalId = readEnvironmentVariable('AZURE_PRINCIPAL_ID', '')
param vaultName = readEnvironmentVariable('AZURE_KEYVAULT_NAME', '')
param managedHsm = bool(readEnvironmentVariable('AZURE_MANAGEDHSM', 'false'))
param resourceGroupName = readEnvironmentVariable('AZURE_RESOURCE_GROUP', 'rg-${environmentName}')
