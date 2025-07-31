# Changelog

## [Unreleased][]

[Unreleased]: https://github.com/trussed-dev/trussed-staging/compare/v0.4.0...HEAD

-

## [v0.4.0][] (2025-07-31)

[v0.4.9]: https://github.com/Nitrokey/trussed-se050-backend/compare/v0.3.6...v0.4.0

### Changed

- Do not close sessions when authentication fails ([#54][])
- Make factory reset power-loss resilient ([#53][])
- Remove duplicate configure ([#55][])
- Update `cbor-smol` dependency to v0.5.0
- Update `littlefs2` dependency to v0.5.0
- Update `se05x` dependency to v0.2.0
- Update `trussed-se050-manage` dependency to v0.2.0

### Added

- Add support for secp256k1 ([#41][])

[#41]: https://github.com/Nitrokey/trussed-se050-backend/pull/41
[#53]: https://github.com/Nitrokey/trussed-se050-backend/pull/53
[#54]: https://github.com/Nitrokey/trussed-se050-backend/pull/54
[#55]: https://github.com/Nitrokey/trussed-se050-backend/pull/55

## [v0.3.6][] (2024-10-17)

[v0.3.6]: https://github.com/Nitrokey/trussed-se050-backend/compare/v0.3.5...v0.3.6

- Add implementation of the `trussed-hpke` extension ([#36][])

[#36]: https://github.com/Nitrokey/trussed-se050-backend/pull/36

## [v0.3.5][] (2024-08-13)

[v0.3.5]: https://github.com/Nitrokey/trussed-se050-backend/compare/v0.3.4...v0.3.5

### Added

- Add support for more curves ([#33](https://github.com/Nitrokey/trussed-se050-backend/pull/33)):
  - NIST P-384
  - Brainpool P-256
  - Brainpool P-384
  - Brainpool P-512

### Changed

- Delete metadata for transient keys ([#34](https://github.com/Nitrokey/trussed-se050-backend/pull/34))

## [v0.3.4][] (2024-07-31)

[v0.3.4]: https://github.com/Nitrokey/trussed-se050-backend/compare/v0.3.3...v0.3.4

No changes.

## [v0.3.3][] (2024-06-21)

[v0.3.3]: https://github.com/Nitrokey/trussed-se050-backend/compare/v0.3.2...v0.3.3

### Changed

- Update `trussed-rsa-alloc` to v0.2.1 ([#32](https://github.com/Nitrokey/trussed-se050-backend/pull/32))

## [v0.3.2][] (2024-06-07)

[v0.3.2]: https://github.com/Nitrokey/trussed-se050-backend/compare/v0.3.1...v0.3.2

### Changed

- Improve inlining of se050 constants ([#20](https://github.com/Nitrokey/trussed-se050-backend/pull/20))
- Make configure method public ([#31](https://github.com/Nitrokey/trussed-se050-backend/pull/31))

### Fixed

- Fully delete application PINs on application factory-reset ([#30](https://github.com/Nitrokey/trussed-se050-backend/pull/30))

## [v0.3.1][] (2024-04-10)

[v0.3.1]: https://github.com/Nitrokey/trussed-se050-backend/compare/v0.3.0...v0.3.1

### Changed

- Remove top-level `dat` folder to reduce filesystem usage ([#16](https://github.com/Nitrokey/trussed-se050-backend/pull/16))
- Update `trussed-auth` to v0.3.0

## [v0.3.0][] (2024-03-15)

[v0.3.0]: https://github.com/Nitrokey/trussed-se050-backend/compare/v0.2.0...v0.3.0

### Changed

- Use extension crates `trussed-manage` and `trussed-wrap-key-to-file` instead
  of backend crate `trussed-staging` ([#13][])
- Move `manage::ManageExtension` into `trussed-se050-manage` crate and rename
  it to `Se050ManageExtension` ([#13][])

[#13]: https://github.com/Nitrokey/trussed-se050-backend/pull/13

## [v0.2.0][] (2024-03-04)

[v0.2.0]: https://github.com/Nitrokey/trussed-se050-backend/compare/v0.1.0...v0.2.0

### Added

- Add support for more RSA operations with the raw mechanism

### Changed

- Update `trussed` dependency

## [v0.1.0][] (2023-11-28)

[v0.1.0]: https://github.com/Nitrokey/trussed-se050-backend/releases/tag/v0.1.0

Initial release providing the Trussed core syscalls and the auth and manage
extensions.
