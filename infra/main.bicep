@description('The vault name; default is a unique string based on the resource group ID')
param vaultName string = uniqueString(resourceGroup().id, 'vault')

@description('User principal ID')
param principalId string

@allowed([ 'standard', 'premium' ])
@description('SKU name; default is standard')
param sku string = 'standard'

@description('Location of the vault; default is the resource group location')
param location string = resourceGroup().location

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
  name: vaultName
  location: location
  properties: {
    tenantId: tenantId
    sku: {
      name: sku
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

  resource ecKey 'keys' = [for ecKey in ecKeys: {
    name: ecKey.name
    properties: {
      kty: 'EC'
      curveName: ecKey.curve
    }
  }]

  resource ecKeyHsm 'keys' = [for ecKey in ecKeys: if (sku == 'premium') {
    name: '${ecKey.name}hsm'
    properties: {
      kty: 'EC-HSM'
      curveName: ecKey.curve
    }
  }]
}

output vaultUri string = vault.properties.vaultUri
