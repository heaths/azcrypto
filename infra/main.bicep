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
param vaultName string = 't${uniqueString(environmentName, 'vault')}'

@allowed([ 'standard', 'premium' ])
@description('SKU name; default is standard')
param sku string = 'standard'

@description('Override the name of the resource group')
param resourceGroupName string = 'rg-${environmentName}'

var tags = {
  'azd-env-name': environmentName
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
    location: location
    principalId: principalId
    sku: sku
    vaultName: vaultName
  }
}

output vaultUri string = resources.outputs.vaultUri
