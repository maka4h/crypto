#!/bin/bash

# Exit script if any command fails
set -e

# Print commands before executing them
set -x

# Check if virtual environment exists, if not create it
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

# Install dependencies if needed
pip install -r requirements.txt

# Run the tests using pytest
python3 -m pytest test_derive_keys.py -v

# Deactivate virtual environment
deactivate

echo "Tests completed successfully!"