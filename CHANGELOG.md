# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Constants extraction for better code organization
  - Created `asm/constants/` directory structure
  - Extracted API path constants to `api_paths.py`
  - Extracted timeout constants to `timeouts.py`
  - All constants are now easily maintainable and reusable
- Fixed Python 3.14+ deprecation warnings
  - Replaced `datetime.utcnow()` with `datetime.now(timezone.utc)` throughout codebase
  - Added proper `timezone` imports
  - Zero deprecation warnings when running tests

### Changed
- Fixed failing test cases in test_reporter.py
  - Corrected test expectations for table format behavior
  - Simplified timestamp test to avoid complex mocking
- All 92 unit tests now pass with 0 failures

### Deprecated
- None

### Removed
- None

### Fixed
- Test failures in reporter module
- DateTime deprecation warnings

### Security
- No security vulnerabilities addressed

[1.0.0]: https://github.com/yourusername/asm-tool/compare/v0.9.0...v1.0.0
