# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [v0.2.0] - 2025-11-20

### Added
- **Signal Protocol Compatibility (Phase 1)**:
  - `PrekeyBundle` structure for X3DH-compatible key exchange.
  - `SignedPrekeyPublic` type with key ID, timestamp, and signature.
  - `CreatePrekeyBundle()` and `VerifyPrekeyBundle()` methods.
  - Signal Protocol terminology aliases: `RotateSignedPrekey()`, `GetActiveSignedPrekey()`, `GetSignedPrekey()`, `GetValidSignedPrekeys()`.
  - `PrekeyStatus` and `PrekeyRotationPolicy` type aliases.
  - `DefaultPrekeyRotationPolicy()` function.
- **Key Rotation & Versioning**: Support for rotating exchange keys while maintaining identity keys.
  - `RotateExchangeKey()` method to generate new exchange key versions.
  - `VersionedExchangeKey` struct with version metadata, timestamps, and lifecycle status.
  - `EncryptWithVersion()` and `DecryptWithKeyPair()` for versioned encryption/decryption.
  - `KeyRotationPolicy` for automatic key expiration and lifecycle management.
  - `ToVersionedPEM()` and `FromPEM()` with automatic migration from legacy format.
  - Comprehensive backward compatibility with legacy single-key format.
- Key lifecycle management methods: `ExpireOldKeys()`, `PruneExpiredKeys()`, `GetValidExchangeKeys()`, `ShouldRotate()`.
- New example: [Key Rotation](examples/key-rotation/main.go) demonstrating all rotation features.

### Changed
- **Documentation**: Updated to use Signal Protocol terminology (prekeys, signed prekeys).
- **README**: Added Signal Protocol compatibility section and references to X3DH specification.
- **BREAKING**: Refactored package structure from sub-packages to a flat structure.
  - All functionality from `keys` and `box` sub-packages is now available directly in the root `e2ee` package.
  - Import path changed from `github.com/tquanghuy/e2ee/keys` and `github.com/tquanghuy/e2ee/box` to `github.com/tquanghuy/e2ee`.
  - Function calls changed from `keys.Generate()` and `box.Encrypt()` to `e2ee.Generate()` and `e2ee.Encrypt()`.
- Updated all documentation and examples to reflect the new package structure.
- `KeyPair` struct now includes `ExchangeKeys` slice and `ActiveExchangeVersion` for versioning support.
- `Generate()` now creates initial exchange key as version 1.
- `FromPEM()` automatically migrates legacy keys to versioned format.

## [v0.1.0] - 2025-11-19

### Added
- Initial release of the `e2ee` SDK.
- `keys` package for generating Identity (Ed25519) and Exchange (X25519) keys.
- `box` package for Authenticated Encryption (Sign-then-Encrypt with XChaCha20-Poly1305).
- `box` package for Digital Signatures (Ed25519).
- Comprehensive documentation and examples.
