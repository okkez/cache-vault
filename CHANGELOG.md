# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.3](https://github.com/okkez/cache-vault/compare/v0.1.2...v0.1.3) - 2025-11-13

### Other

- *(deps)* update taiki-e/install-action action to v2.62.50
- *(deps)* update taiki-e/install-action action to v2.62.49
- *(deps)* update taiki-e/install-action action to v2.62.47
- *(deps)* update taiki-e/install-action action to v2.62.46
- *(deps)* update taiki-e/install-action action to v2.62.39
- *(deps)* update taiki-e/install-action action to v2.62.38
- *(deps)* update taiki-e/install-action action to v2.62.36
- *(deps)* update taiki-e/install-action action to v2.62.35

## [0.1.2](https://github.com/okkez/cache-vault/compare/v0.1.1...v0.1.2) - 2025-09-15

### Fixed

- Adapt to keyring v3 API changes
- *(deps)* update rust crate keyring to v3
- *(deps)* update rust crate dirs to v6
- return correct id on upsert

### Other

- Merge pull request #8 from okkez/renovate/dirs-6.x
- *(deps)* update actions/create-github-app-token action to v2.1.4
- Merge pull request #42 from okkez/fix/upsert-last-insert-id
- create database file before migration
- use absolute path for sqlite database
- use file-based sqlite database
- run migrations before preparing sqlx
- set DATABASE_URL for test and check jobs
- run cargo sqlx prepare
- update
- Merge pull request #11 from okkez/renovate/thiserror-2.x
- Merge pull request #38 from okkez/renovate/marcoieni-release-plz-action-0.x
- *(deps)* update taiki-e/install-action action to v2.61.0
- *(deps)* update taiki-e/install-action action to v2.60.0
- Merge pull request #35 from okkez/renovate/taiki-e-install-action-2.x
- *(deps)* update marcoieni/release-plz-action action to v0.5.114
- *(deps)* update taiki-e/install-action action to v2.58.32
- *(deps)* update taiki-e/install-action action to v2.58.31
- Merge pull request #31 from okkez/renovate/marcoieni-release-plz-action-0.x
- *(deps)* update taiki-e/install-action action to v2.58.30
- *(deps)* update taiki-e/install-action action to v2.58.29
- *(deps)* update taiki-e/install-action action to v2.58.26
- *(deps)* update taiki-e/install-action action to v2.58.25
- *(deps)* update taiki-e/install-action action to v2.58.21
- Merge pull request #24 from okkez/renovate/marcoieni-release-plz-action-0.x
- *(deps)* update taiki-e/install-action action to v2.58.17
- Merge pull request #20 from okkez/renovate/actions-create-github-app-token-2.x
- Merge pull request #19 from okkez/renovate/taiki-e-install-action-2.x
- *(deps)* update actions/checkout action to v5
- *(deps)* update actions/checkout action to v4.3.0
- *(deps)* update taiki-e/install-action action to v2.57.1
- *(deps)* update taiki-e/install-action action to v2.56.24
- Merge pull request #15 from okkez/renovate/marcoieni-release-plz-action-0.x
- *(deps)* update taiki-e/install-action action to v2.56.23
- fix
- Pin actions
- *(deps)* update actions/create-github-app-token action to v2

## [0.1.1](https://github.com/okkez/cache-vault/compare/v0.1.0...v0.1.1) - 2025-01-01

### Added

- add tracing crate

### Other

- update README.md
- use tracing-test

## [0.1.0](https://github.com/okkez/cache-vault/releases/tag/v0.1.0) - 2024-12-27

### Added

- first implementation

### Other

- update gitignore
- linux-default-keyutils
- prepare database
- setup database properly
- install sqlx-cli
- run cargo sqlx prepare
- add DATABASE_URL
- add DATABASE_URL
- remove example
- add github actions
- set max_width = 120 and run cargo fmt
- Initial commit
