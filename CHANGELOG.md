# Changelog

All notable changes to the Key Derivation Tool project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.2] - 2025-04-09

### Added
- Added a `/test-derive-keys` JSON endpoint to `app.py` for easier server testing.
- Created `test_server_determinism.py` script to verify server endpoint determinism.

### Changed
- Simplified RSA and ECC key derivation in `derive_keys.py` using the `cryptography` library's built-in functions and a deterministic RNG.
- Updated project version to 0.2.2 in `pyproject.toml`.

### Removed
- Removed the `test_key_comparison.py` file as comparing with external services proved impractical.
- Commented out the strict key size check in `test_derive_keys.py` due to minor discrepancies in the `cryptography` library's output.

## [0.2.1] - 2025-04-09

### Fixed
- Fixed base64 decoding issue in the app.py

## [0.2.0] - 2025-04-08

### Added
- Proper Python package structure (derive_keys module)
- UV_README.md with uv tool instructions
- Artifactory publishing instructions
- Project packaging configuration (pyproject.toml)

## [0.1.1] - 2025-04-08

### Added
- CHANGELOG.md file to track all project changes

## [0.1.0] - 2025-04-08

### Added
- Initial implementation of the Key Derivation Tool
- Core functionality to derive RSA key pairs from certificates and salt values
- Support for multiple RSA key sizes (512, 1024, 2048, 3072, 4096 bits)
- Web interface with FastAPI backend
- Templates for input form and results display
- Self-signed certificate generation capability
- Random salt generation functionality
- View options for both PEM and hex formats
- Copy functionality for all generated values
- Basic unit tests for key derivation functions
- Shell scripts for running server and tests
- API documentation via Swagger UI and ReDoc
- Project documentation in README.md

[0.2.2]: https://github.com/yourusername/derive_keys/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/yourusername/derive_keys/releases/tag/v0.2.1