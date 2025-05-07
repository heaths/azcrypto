@description('The vault name.')
param vaultName string

@description('Whether to provision a Key Vault (per-call billing) or Managed HSM (lifetime billing).')
param managedHsm bool = false

var keys = [
  {
    name: 'ec256'
    kty: 'EC'
    curve: 'P-256'
  }
  {
    name: 'ec384'
    kty: 'EC'
    curve: 'P-384'
  }
  {
    name: 'ec521'
    kty: 'EC'
    curve: 'P-521'
  }
  {
    name: 'rsa2048'
    kty: 'RSA'
    size: 2048
  }
]

resource kvKeys 'Microsoft.KeyVault/vaults/keys@2023-02-01' = [for key in keys: if (!managedHsm) {
  name: '${vaultName}/${key.name}'
  properties: {
    kty: key.kty
    curveName: key.?curve
    keySize: key.?size
  }
}]

resource hsmKeys 'Microsoft.KeyVault/managedHSMs/keys@2023-02-01' = [for key in keys: if (managedHsm) {
  name: '${vaultName}/${key.name}'
  properties: {
    kty: key.kty
    curveName: key.?curve
    keySize: key.?size
  }
}]

resource hsmOctKeys 'Microsoft.KeyVault/managedHSMs/keys@2023-02-01' = [for size in [128, 192, 256]: if (managedHsm) {
  name: '${vaultName}/aes${size}'
  properties: {
    kty: 'oct'
    keySize: size
  }
}]
