# Sovereign-Sync: Basic Integration Guide

## Quick Start with Core Request-Response Lifecycle

This `main.py` provides a simplified version of Sovereign-Sync that focuses on the essential privacy gateway functionality.

### Setup

1. **Install dependencies:**
```bash
pip install -r requirements.txt
```

2. **Configure API keys:**
```bash
cp .env.template .env
# Edit .env with your Gemini API key (AIza...)
```

3. **Build C library (optional):**
```bash
mkdir build && cd build
cmake ..
make
```

### Usage

**Start the gateway:**
```bash
python main.py
```

**Test PII protection:**
```bash
curl -X POST http://localhost:8000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gemini-2.0-flash",
    "messages": [
      {
        "role": "user",
        "content": "My Aadhar number is 1234-5678-9012. What can I do with it?"
      }
    ]
  }'
```

### How It Works

1. **Tokenization**: Incoming PII (Aadhar, PAN, Phone) is detected and replaced with tokens like `[AADHAR_1000]`
2. **API Forwarding**: The masked request is sent to Google Gemini
3. **Rehydration**: AI response tokens are replaced with original PII values
4. **Cleanup**: Vault is immediately cleared after response (zero-trust)

### Key Features

- ✅ **PrivacyVault integration** with automatic tokenization
- ✅ **Live Gemini API calls** with secure key handling via .env
- ✅ **Rehydration loop** that restores original PII in responses
- ✅ **Session cleanup** - vault purged after each request
- ✅ **Fallback PII detection** if C library unavailable

### Environment Variables

```bash
# Required
GEMINI_API_KEY=your_key_here

# Optional
DEFAULT_MODEL=gemini-2.0-flash
HOST=127.0.0.1
PORT=8000
```

This basic integration gives you a working privacy gateway that you can build upon for the hackathon!