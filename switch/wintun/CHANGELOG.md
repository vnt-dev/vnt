# ChangeLog

This format is based on [Keep a Changelog](https://keepachangelog.com/)
and this project adheres to [Semantic Versioning](https://semver.org).

## [0.2.1] - 2021-12-03

### Fixed
Type in readme

## [0.2.0] - 2021-12-03

Added support for wintun 0.14.

### Breaking Changes

- Wintun driver versions before `0.14` are no longer support due to beraking
changes in the C API
- `Adapter::create` returns a `Result<Adapter, ...>` instead of a `Result<CreateData, ...>`.
This was done because the underlying Wintun function was changed to only return an adapter handle
- `Adapter::create` the pool parameter was removed because it was also removed from the C function
- `Adapter::delete` takes no parameters and returns a `Result<(), ()>`.
The `force_close_sessions` parameter was removed because it was removed from the
C function. Same for the bool inside the Ok(..) variant
- `Adapter::create` and `Adapter::open` return `Arc<Adapter>` instead of `Adapter`
- `get_running_driver_version` now returns a proper Result<Version, ()>. 

### Added

- `reset_logger` function to disable logging after a logger has been set.

## [0.1.5] - 2021-08-27

### Fixed

- Readme on crates.io

## [0.1.4] - 2021-08-27

### Added
- `panic_on_unsent_packets` feature flag to help in debugging ring buffer blockage issues

## [0.1.3] - 2021-06-28

### Fixed

- Cargo.toml metadata to include `package.metadata.docs.rs.default-target`.
Fixes build issue on docs.rs (we can only build docs on windows, 0.1.1 doesn't work)

## [0.1.2] - 2021-06-28
docs.rs testing

## [0.1.1] - 2021-06-28

- Cargo.toml metadata to build on linux

## [0.1.0] - 2021-06-28

First release with initial api

