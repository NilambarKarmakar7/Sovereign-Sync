#!/bin/bash

# Sovereign-Sync Auto-Build Script
# Automated setup for FOSS Hack 2026 judges and developers

set -e  # Exit on any error

echo "🚀 Sovereign-Sync Auto-Build Script"
echo "=================================="

# Check if we're in the right directory
if [ ! -f "main.py" ] || [ ! -f "pii_filter.c" ]; then
    echo "❌ Error: Please run this script from the Sovereign-Sync root directory"
    echo "   Expected files: main.py, pii_filter.c"
    exit 1
fi

echo "✅ Found Sovereign-Sync project files"

# Check for required tools
echo ""
echo "🔍 Checking system requirements..."

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 not found. Please install Python 3.8+"
    exit 1
fi
echo "✅ Python 3 found: $(python3 --version)"

# Check pip
if ! command -v pip3 &> /dev/null; then
    echo "❌ pip3 not found. Please install pip3"
    exit 1
fi
echo "✅ pip3 found"

# Check GCC
if ! command -v gcc &> /dev/null; then
    echo "❌ GCC not found. Please install GCC (build-essential on Ubuntu/Debian)"
    exit 1
fi
echo "✅ GCC found: $(gcc --version | head -n1)"

echo ""
echo "📦 Installing system dependencies..."

# Install PCRE2 dev headers (Ubuntu/Debian)
if command -v apt-get &> /dev/null; then
    sudo apt-get update && sudo apt-get install -y libpcre2-dev
fi

echo "📦 Installing Python dependencies..."

# Install Python requirements
pip3 install -r requirements.txt

echo "✅ Python dependencies installed"

echo ""
echo "🔨 Compiling C PII detection module..."

# Compile the C module
gcc -shared -fPIC -o pii_filter.so pii_filter.c -lpcre2-8

if [ $? -eq 0 ]; then
    echo "✅ C module compiled successfully: pii_filter.so"
else
    echo "❌ C compilation failed"
    exit 1
fi

echo ""
echo "🔍 Verifying installation..."

# Quick verification
if [ -f "pii_filter.so" ]; then
    echo "✅ pii_filter.so exists"
else
    echo "❌ pii_filter.so not found after compilation"
    exit 1
fi

# Test Python imports
python3 -c "
import sys
sys.path.append('.')
try:
    import vault
    print('✅ vault.py imports successfully')
except ImportError as e:
    print(f'❌ vault.py import failed: {e}')
    sys.exit(1)

try:
    import ctypes
    lib = ctypes.CDLL('./pii_filter.so')
    print('✅ pii_filter.so loads successfully')
except Exception as e:
    print(f'❌ pii_filter.so load failed: {e}')
    sys.exit(1)
"

echo ""
echo "🎉 Sovereign-Sync setup complete!"
echo ""
echo "🚀 To start the server:"
echo "   export OPENAI_API_KEY='your-api-key-here'"
echo "   python3 main.py"
echo ""
echo "📖 For more information, see README.md"
echo ""
echo "🔒 Remember: Never commit API keys to version control!"