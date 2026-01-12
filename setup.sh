#!/bin/bash

# AI-Powered Phishing Analyzer Setup Script
# This script sets up the environment and installs all dependencies

set -e  # Exit on error

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                                                               ║"
echo "║        🛡️  AI-Powered Phishing Analyzer Setup 🛡️            ║"
echo "║                                                               ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

# Check Python version
echo "🔍 Checking Python version..."
if ! command -v python3 &> /dev/null; then
    echo "❌ Error: Python 3 is not installed"
    echo "Please install Python 3.8 or higher from https://www.python.org/"
    exit 1
fi

PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
echo "✓ Found Python $PYTHON_VERSION"

# Check if python version is 3.8+
MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)

if [ "$MAJOR" -lt 3 ] || ([ "$MAJOR" -eq 3 ] && [ "$MINOR" -lt 8 ]); then
    echo "❌ Error: Python 3.8 or higher is required"
    echo "Current version: $PYTHON_VERSION"
    exit 1
fi

# Create virtual environment
echo ""
echo "📦 Creating virtual environment..."
if [ -d "venv" ]; then
    echo "⚠️  Virtual environment already exists. Removing old one..."
    rm -rf venv
fi

python3 -m venv venv
echo "✓ Virtual environment created"

# Activate virtual environment
echo ""
echo "🔄 Activating virtual environment..."
source venv/bin/activate
echo "✓ Virtual environment activated"

# Upgrade pip
echo ""
echo "⬆️  Upgrading pip..."
pip install --upgrade pip > /dev/null 2>&1
echo "✓ pip upgraded"

# Install dependencies
echo ""
echo "📥 Installing dependencies (this may take a few minutes)..."
echo ""

pip install -r requirements.txt

if [ $? -eq 0 ]; then
    echo ""
    echo "✓ All dependencies installed successfully"
else
    echo ""
    echo "❌ Error installing dependencies"
    exit 1
fi

# Download NLTK data
echo ""
echo "📚 Downloading NLP data..."
python3 << EOF
import nltk
import sys

try:
    print("Downloading NLTK data...")
    nltk.download('punkt', quiet=True)
    nltk.download('stopwords', quiet=True)
    nltk.download('averaged_perceptron_tagger', quiet=True)
    nltk.download('vader_lexicon', quiet=True)
    print("✓ NLTK data downloaded")
except Exception as e:
    print(f"⚠️  Warning: Some NLTK data may not have downloaded: {e}")
    sys.exit(0)  # Don't fail setup for this
EOF

# Create config file if it doesn't exist
echo ""
echo "⚙️  Setting up configuration..."
if [ ! -f "config.yaml" ]; then
    cp config.example.yaml config.yaml
    echo "✓ Created config.yaml from template"
    echo ""
    echo "⚠️  IMPORTANT: Edit config.yaml and add your API keys:"
    echo "   - OpenAI API key (required for AI analysis)"
    echo "   - Have I Been Pwned API key (optional)"
else
    echo "✓ config.yaml already exists"
fi

# Make scripts executable
echo ""
echo "🔧 Making scripts executable..."
chmod +x cli.py
chmod +x gui.py
chmod +x run_cli.sh
chmod +x run_gui.sh
echo "✓ Scripts are now executable"

# Create directories
echo ""
echo "📁 Creating output directories..."
mkdir -p results
mkdir -p logs
echo "✓ Directories created"

# Success message
echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                                                               ║"
echo "║                    ✅ SETUP COMPLETE! ✅                      ║"
echo "║                                                               ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""
echo "📝 Next steps:"
echo ""
echo "1. Configure your API keys:"
echo "   nano config.yaml"
echo ""
echo "2. Run the GUI:"
echo "   ./run_gui.sh"
echo "   or: python3 gui.py"
echo ""
echo "3. Or use the CLI:"
echo "   ./run_cli.sh --help"
echo "   or: python3 cli.py --help"
echo ""
echo "📖 For more information, see README.md"
echo ""
echo "🛡️  Stay safe online!"
echo ""
