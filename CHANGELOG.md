# Changelog

All notable changes to the Key Derivation Tool project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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