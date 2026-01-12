#!/bin/bash

# Quick start script for CLI interface

# Activate virtual environment if it exists
if [ -d "venv" ]; then
    source venv/bin/activate
fi

# Run CLI with provided arguments
python3 cli.py "$@"
