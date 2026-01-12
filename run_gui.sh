#!/bin/bash

# Quick start script for GUI interface

echo "Starting AI-Powered Phishing Analyzer GUI..."
echo ""

# Activate virtual environment if it exists
if [ -d "venv" ]; then
    source venv/bin/activate
fi

# Run GUI
python3 gui.py
