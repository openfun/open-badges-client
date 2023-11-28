# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic
Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2.1.0] - 2023-11-28

### Added

- OBF: Add and improve logs when wrong status code received

### Changed

- OBF: Remove email validation of `BadgeIssue.recipient` field

## [2.0.0] - 2023-11-02

### Changed

- OBF: `BadgeRevokation` is replaced by `BadgeRevocation` [BC]
- OBF: modified `OBFBadge`, `OBFAssertion` and `OBFEvent` CRUD methods to take
IDs as input parameters when sufficient instead of whole objects [BC]
- OBF: raise a `BadgeProviderError` if `read` methods cannot yield objects
- OBF: `BadgeIssue` params `badge_override` and `log_entry` now accept strings

## [1.0.0] - 2023-09-06

### Added

- Add `events` and `assertions` attributes to OBF provider
- Add `read` method for `events` and `assertions` attributes of OBF provider 

### Changed

- Change providers methods to be asynchronous [BC]
- Return a `BadgeIssue` instance in the `issue` method [BC]
- Move badges methods to a `badges` attribute of OBF provider [BC]
- Change from `requests` to `httpx` for API requests

## [0.2.1] - 2023-08-23

### Changed

- Remove deserialization of empty JSON lines

## [0.2.0] - 2023-08-07

### Changed

- Migrate to pydantic v2

## [0.1.0] - 2023-02-03

### Added

- Extract the OBF badge provider from the Joanie project

[Unreleased]: https://github.com/openfun/open-badges-client/compare/v2.1.0...main
[2.1.0]: https://github.com/openfun/open-badges-client/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/openfun/open-badges-client/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/openfun/open-badges-client/compare/v0.2.1...v1.0.0
[0.2.1]: https://github.com/openfun/open-badges-client/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/openfun/open-badges-client/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/openfun/open-badges-client/compare/a253313...v0.1.0
