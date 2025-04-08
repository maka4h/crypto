#!/bin/bash

# Exit script if any command fails
set -e

# Check if virtual environment exists, if not create it
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the FastAPI application with uvicorn
echo "Starting FastAPI server on http://localhost:8000"
uvicorn app:app --host 0.0.0.0 --port 8000 --reload

# Note: This line won't be reached while the server is running
# To stop the server, press Ctrl+C