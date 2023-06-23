# Release History

## 0.5.0 (Unreleased)

### Features Added

- Added support for `oct` and `oct-HSM` keys using AES for Azure Managed HSM.
  - Added `EncryptAESCBC` function to `Client`.
  - Added `EncryptAESGCM` function to `Client`.
  - Added `EncryptAESCBCAlgorithm` enumeration for `EncryptAESCBC`.
  - Added `EncryptAESGCMAlgorithm` enumeration for `EncryptAESGCM`.
  - Added `WrapKeyAlgorithmA128KW`, `WrapKeyAlgorithmA192KW`, and `WrapKeyAlgorithmA256KW` enumeration for `WrapKey`.

### Breaking Changes

- Renamed `EncryptionAlgorithm` to `EncryptAlgorithm`.
- Renamed `SignatureAlgorithm` to `SignAlgorithm`.
- Renamed `KeyWrapAlgorithm` to `WrapKeyAlgorithm`.
