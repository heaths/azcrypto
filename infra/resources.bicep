@minLength(1)
@maxLength(64)
@description('Name of the the environment which is used to generate a short unique hash used in all resources.')
param environmentName string

@minLength(1)
@description('Primary location for all resources')
param location string = resourceGroup().location

@description('User principal ID')
param principalId string

@description('The vault name; default is a unique string based on the resource group ID')
param vaultName string = ''

var finalVaultName = empty(vaultName) ? 't${uniqueString(resourceGroup().id, environmentName)}' : vaultName
var tenantId = subscription().tenantId
var ecKeys = [
  {
    name: 'ec256'
    curve: 'P-256'
  }
  {
    name: 'ec384'
    curve: 'P-384'
  }
  {
    name: 'ec521'
    curve: 'P-521'
  }
]

resource vault 'Microsoft.KeyVault/vaults@2023-02-01' = {
  name: finalVaultName
  location: location
  properties: {
    tenantId: tenantId
    sku: {
      name: 'standard'
      family: 'A'
    }
    // Use access policies since RBAC assignments may not propogate in time.
    // TODO: Consider using nested RBAC deployment to allow additional time.
    accessPolicies: [
      {
        objectId: principalId
        permissions: {
          keys: [
            'create'
            'list'
            'get'
            'encrypt'
            'decrypt'
            'sign'
            'verify'
            'wrapKey'
            'unwrapKey'
          ]
        }
        tenantId: tenantId
      }
    ]
  }

  resource ecKey 'keys' = [for key in ecKeys: {
    name: key.name
    properties: {
      kty: 'EC'
      curveName: key.curve
    }
  }]

  resource rsaKey 'keys' = {
    name: 'rsa2048'
    properties: {
      kty: 'RSA'
      keySize: 2048
    }
  }
}

output AZURE_KEYVAULT_NAME string = vault.name
output AZURE_KEYVAULT_URL string = vault.properties.vaultUri

