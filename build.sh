#!/usr/bin/env bash

# Create and activate virtual environment
python -m venv venv
source venv/bin/activate

# Install dependencies with optimizations
pip install --upgrade pip
pip install --no-cache-dir -r requirements.txt

# Create necessary directories
mkdir -p database
mkdir -p database/backups

# Initialize the database
python create_db.py 