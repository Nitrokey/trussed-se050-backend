# Changelog

## Unreleased

### Changed

- Use extension crates `trussed-manage` and `trussed-wrap-key-to-file` instead
  of backend crate `trussed-staging`, see [trussed-staging#19][].
- Move `manage::ManageExtension` into `trussed-se050-manage` crate and rename
  it to `Se050ManageExtension`.

[trussed-staging#19]: https://github.com/trussed-dev/trussed-staging/pull/19

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
