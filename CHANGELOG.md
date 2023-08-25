# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic
Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Return a `BadgeIssue` instance in the `issue` method [BC]
- Add a `badges` attribute to OBF provider for badges methods [BC]
- Add `events` and `assertions` attributes to OBF provider
- Add `read` method for `events` and `assertions` attributes of OBF provider 

## [0.2.1] - 2023-08-23

### Changed

- Remove deserialization of empty JSON lines

## [0.2.0] - 2023-08-07

### Changed

- Migrate to pydantic v2

## [0.1.0] - 2023-02-03

### Added

- Extract the OBF badge provider from the Joanie project

[Unreleased]: https://github.com/openfun/open-badges-client/compare/v0.2.1...main
[0.2.1]: https://github.com/openfun/open-badges-client/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/openfun/open-badges-client/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/openfun/open-badges-client/compare/a253313...v0.1.0
