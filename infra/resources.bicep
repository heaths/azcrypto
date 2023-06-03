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

@description('Whether to provision a Key Vault (per-call billing) or Managed HSM (lifetime billing).')
param managedHsm bool = false

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

resource vault 'Microsoft.KeyVault/vaults@2023-02-01' = if (!managedHsm) {
  name: finalVaultName
  location: location
  properties: {
    tenantId: tenantId
    sku: {
      name: 'standard'
      family: 'A'
    }
    enableRbacAuthorization: true
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

var kvCryptoUserDefinitionId = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '12338af0-0e69-4776-bea7-57ae8d297424')

resource rbac 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (!managedHsm) {
  name: guid(resourceGroup().id, environmentName, principalId, kvCryptoUserDefinitionId)
  scope: vault
  properties: {
    roleDefinitionId: kvCryptoUserDefinitionId
    principalId: principalId
  }
}

resource hsm 'Microsoft.KeyVault/managedHSMs@2023-02-01' = if (managedHsm) {
  name: finalVaultName
  location: location
  sku: {
    name: 'Standard_B1'
    family: 'B'
  }
  properties: {
    tenantId: tenantId
    initialAdminObjectIds: [
      principalId
    ]
  }

  // Key management operations require AllowKeyManagementOperationsThroughARM.
}

output AZURE_PRINCIPAL_ID string = principalId
output AZURE_KEYVAULT_NAME string = managedHsm ? hsm.name : vault.name
output AZURE_KEYVAULT_URL string = managedHsm ? hsm.properties.hsmUri : vault.properties.vaultUri
output AZURE_MANAGEDHSM bool = managedHsm
