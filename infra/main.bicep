targetScope = 'subscription'

@minLength(1)
@maxLength(64)
@description('Name of the the environment which is used to generate a short unique hash used in all resources.')
param environmentName string

@minLength(1)
@description('Primary location for all resources')
param location string

@description('User principal ID')
param principalId string

@description('The vault name; default is a unique string based on the resource group ID')
param vaultName string = ''

@description('Whether to provision a Key Vault (per-call billing) or Managed HSM (lifetime billing).')
param managedHsm bool = false

@description('Override the name of the resource group')
param resourceGroupName string = 'rg-${environmentName}'

@description('How long until the resource group is cleaned up by automated processes.')
param deleteAfterTime string = dateTimeAdd(utcNow('o'), 'P1D')

var tags = {
  'azd-env-name': environmentName
  DeleteAfter: deleteAfterTime
}

resource rg 'Microsoft.Resources/resourceGroups@2022-09-01' = {
  name: resourceGroupName
  location: location
  tags: tags
}

module resources 'resources.bicep' = {
  name: 'resources'
  scope: rg
  params: {
    environmentName: environmentName
    location: location
    principalId: principalId
    vaultName: vaultName
    managedHsm: managedHsm
  }
}

output AZURE_PRINCIPAL_ID string = resources.outputs.AZURE_PRINCIPAL_ID
output AZURE_RESOURCE_GROUP string = resourceGroupName
output AZURE_KEYVAULT_NAME string = resources.outputs.AZURE_KEYVAULT_NAME
output AZURE_KEYVAULT_URL string = resources.outputs.AZURE_KEYVAULT_URL
