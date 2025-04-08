# Managing the Derive Keys Project with UV

This document provides instructions for managing the Derive Keys project using [`uv`](https://github.com/astral-sh/uv), a fast, reliable Python package manager and resolver.

## Table of Contents

1. [Installation of UV](#installation)
2. [Project Setup](#project-setup)
3. [Development Workflow](#development-workflow)
4. [Testing](#testing)
5. [Building the Package](#building-the-package)
6. [Publishing to Local Artifactory](#publishing-to-local-artifactory)
7. [Useful UV Commands](#useful-uv-commands)

## Installation

### Installing UV

```bash
# On macOS
brew install uv

# On Linux
curl -LsSf https://astral.sh/uv/install.sh | sh

# On Windows
powershell -c "irm https://astral.sh/uv/install.ps1 | iex"
```

Verify the installation:

```bash
uv --version
```

## Project Setup

### Create a Virtual Environment

```bash
# Create a virtual environment in the .venv directory
uv venv

# Activate the virtual environment
source .venv/bin/activate  # Unix
.venv\Scripts\activate     # Windows
```

### Install Dependencies

```bash
# Install project dependencies
uv pip install -e .

# Install development dependencies
uv pip install pytest pytest-cov black isort mypy
```

## Development Workflow

### Managing Dependencies

Add/update dependencies in `pyproject.toml` then run:

```bash
# Sync dependencies with pyproject.toml
uv pip install -e .
```

### Code Formatting

```bash
# Format code
uv run black .
uv run isort .
```

### Type Checking

```bash
# Run type checking
uv run mypy .
```

## Testing

```bash
# Run tests
uv run pytest

# Run tests with coverage
uv run pytest --cov=derive_keys
```

## Building the Package

```bash
# Build source distribution and wheel
uv build
```

This will create artifacts in the `dist/` directory:
- `derive_keys-0.2.0.tar.gz` (source distribution)
- `derive_keys-0.2.0-py3-none-any.whl` (wheel)

## Publishing to Local Artifactory

### Configure Authentication

Create or edit `~/.pypirc` file with your Artifactory credentials:

```ini
[distutils]
index-servers =
    local-artifactory

[local-artifactory]
repository: https://your-artifactory-server/artifactory/api/pypi/pypi-local
username: your-username
password: your-password
```

Alternatively, you can set environment variables:

```bash
export ARTIFACTORY_URL=https://your-artifactory-server/artifactory/api/pypi/pypi-local
export ARTIFACTORY_USERNAME=your-username
export ARTIFACTORY_PASSWORD=your-password
```

### Publish the Package

Using `uv` directly:

```bash
# Publish using uv (if your uv version supports publishing)
uv publish --repository local-artifactory
```

If `uv publish` is not available in your version, you can use `twine` with `uv`:

```bash
# Install twine
uv pip install twine

# Upload using twine
uv run twine upload --repository local-artifactory dist/*
```

### Verify Publication

You can verify your package was published successfully by installing it from your Artifactory:

```bash
uv pip install --index-url https://your-artifactory-server/artifactory/api/pypi/pypi-local derive_keys==0.2.0
```

## Useful UV Commands

### General Commands

```bash
# List installed packages
uv pip list

# Show package details
uv pip show derive_keys

# Upgrade uv itself
uv self update
```

### Environment Management

```bash
# Export dependencies to requirements.txt
uv pip freeze > requirements.txt

# Create a new virtual environment with specific Python version
uv venv --python=python3.10
```

### Performance Tips

- Use `uv pip sync requirements.txt` to ensure exact versions are installed
- Use `uv pip install --upgrade-package package_name` to upgrade a specific package
- Enable caching to speed up future installations: `uv pip install --cache-dir=.cache`

## CI/CD Integration

For CI/CD pipelines, you can add the following to your workflow:

```yaml
- name: Set up Python
  uses: actions/setup-python@v4
  with:
    python-version: '3.10'

- name: Install uv
  run: curl -LsSf https://astral.sh/uv/install.sh | sh

- name: Install dependencies
  run: uv pip install -e . pytest

- name: Run tests
  run: uv run pytest

- name: Build package
  run: uv build

- name: Publish to Artifactory
  run: |
    uv pip install twine
    uv run twine upload --repository-url $ARTIFACTORY_URL -u $ARTIFACTORY_USERNAME -p $ARTIFACTORY_PASSWORD dist/*
  env:
    ARTIFACTORY_URL: ${{ secrets.ARTIFACTORY_URL }}
    ARTIFACTORY_USERNAME: ${{ secrets.ARTIFACTORY_USERNAME }}
    ARTIFACTORY_PASSWORD: ${{ secrets.ARTIFACTORY_PASSWORD }}
```

## Troubleshooting

### Common Issues

1. **SSL Certificate Verification Failed**: Add the `--no-verify-ssl` flag to `uv pip` commands if your Artifactory uses self-signed certificates.

2. **Authentication Issues**: Check that your credentials are correct in `~/.pypirc` or environment variables.

3. **Version Conflicts**: Use `uv pip install --constraint=constraints.txt` to enforce specific versions.

4. **Cache Problems**: Clear the cache with `uv cache clear`.