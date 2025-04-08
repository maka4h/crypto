# Key Derivation Tool

A web-based tool for deriving cryptographic key pairs from certificate PEM and salt values using RSA algorithm. This application allows you to generate, view, and copy cryptographic keys in different formats (PEM and hex).

## Features

- Generate RSA key pairs based on certificate PEM and salt values
- Support for different RSA key sizes (512, 1024, 2048, 3072, 4096 bits)
- Generate self-signed certificates on-the-fly
- Generate random salt values
- View keys in both PEM and hex formats
- Copy functionality for all generated values
- Interactive web interface with tabs for different formats

## Installation

1. Clone this repository
2. Create a virtual environment:
   ```bash
   python3 -m venv venv
   ```

3. Activate the virtual environment:
   ```bash
   source venv/bin/activate
   ```

4. Install the dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Running the Server

Execute the provided shell script to start the FastAPI server:

```bash
./run_server.sh
```

Then open your browser and navigate to:
```
http://localhost:8000
```

### Running the Tests

Execute the provided shell script to run the unit tests:

```bash
./run_tests.sh
```

### API Documentation

The application includes Swagger UI documentation available at:

```
http://localhost:8000/docs
```

You can also access the ReDoc documentation at:

```
http://localhost:8000/redoc
```

## Project Structure

- `app.py` - Main FastAPI application
- `derive_keys.py` - Core key derivation functionality
- `test_derive_keys.py` - Unit tests for key derivation
- `templates/` - HTML templates for the web interface
  - `index.html` - Input form for key derivation
  - `result.html` - Display page for derived keys
- `requirements.txt` - Project dependencies
- `run_server.sh` - Script to run the server
- `run_tests.sh` - Script to run the tests

## Dependencies

- FastAPI - Web framework
- Cryptography - For cryptographic operations
- Uvicorn - ASGI server
- Jinja2 - Template engine
- pytest - Testing framework

## License

This project is licensed under the MIT License.