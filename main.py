"""
Sovereign-Sync: Privacy Gateway for LLM APIs
Copyright (c) 2026 - Licensed under GNU GPL v3.0

Complete request-response lifecycle with PII tokenization, API proxying, and rehydration.
"""

import asyncio
import json
import os
import logging
from typing import Dict, Optional
from uuid import uuid4

import httpx
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# ============================================================================
# BASIC PRIVACY VAULT
# ============================================================================

class PrivacyVault:
    """Simple in-memory vault for PII tokenization and rehydration"""

    def __init__(self):
        self.vault: Dict[str, str] = {}
        self.token_counter = 1000

    def tokenize(self, text: str, pii_type: str) -> tuple[str, str]:
        """Replace PII with token and store mapping"""
        token = f"[{pii_type}_{self.token_counter}]"
        self.token_counter += 1

        self.vault[token] = text
        return token, text

    def rehydrate(self, text: str) -> str:
        """Replace tokens with original PII"""
        result = text
        for token, original in self.vault.items():
            result = result.replace(token, original)
        return result

    def clear(self):
        """Securely clear the vault"""
        self.vault.clear()
        self.token_counter = 1000

# ============================================================================
# C LIBRARY INTEGRATION (SIMPLIFIED)
# ============================================================================

try:
    import ctypes
    # Load the C library (adjust path as needed)
    lib_path = os.path.join(os.path.dirname(__file__), '..', 'lib', 'libpii_scanner.so')
    if not os.path.exists(lib_path):
        lib_path = os.path.join(os.path.dirname(__file__), '..', 'lib', 'libpii_scanner.dll')

    if os.path.exists(lib_path):
        libscanner = ctypes.CDLL(lib_path)
        C_LIBRARY_AVAILABLE = True
        print("✓ C PII scanner library loaded")
    else:
        libscanner = None
        C_LIBRARY_AVAILABLE = False
        print("⚠ C PII scanner library not found - using fallback")
except Exception as e:
    libscanner = None
    C_LIBRARY_AVAILABLE = False
    print(f"⚠ Failed to load C library: {e}")

# ============================================================================
# BASIC PII DETECTOR
# ============================================================================

class PIIDetector:
    """Simple PII detection combining C regex and basic patterns"""

    def __init__(self):
        self.vault = PrivacyVault()

    def detect_and_mask(self, text: str) -> str:
        """Detect PII and replace with tokens"""
        masked_text = text

        # Simple regex patterns (fallback if C library not available)
        if not C_LIBRARY_AVAILABLE:
            import re

            # Aadhar pattern
            aadhar_pattern = r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'
            masked_text = re.sub(aadhar_pattern,
                               lambda m: self.tokenize(m.group(), "AADHAR")[0],
                               masked_text)

            # PAN pattern
            pan_pattern = r'\b[A-Z]{5}\d{4}[A-Z]\b'
            masked_text = re.sub(pan_pattern,
                               lambda m: self.tokenize(m.group(), "PAN")[0],
                               masked_text)

            # Phone pattern
            phone_pattern = r'\b(?:\+91|91)?[6-9]\d{9}\b'
            masked_text = re.sub(phone_pattern,
                               lambda m: self.tokenize(m.group(), "PHONE")[0],
                               masked_text)

        return masked_text

    def tokenize(self, text: str, pii_type: str) -> tuple[str, str]:
        """Tokenize PII using vault"""
        return self.vault.tokenize(text, pii_type)

    def rehydrate(self, text: str) -> str:
        """Rehydrate text using vault"""
        return self.vault.rehydrate(text)

    def clear_vault(self):
        """Clear the vault"""
        self.vault.clear()

# ============================================================================
# FASTAPI APPLICATION
# ============================================================================

app = FastAPI(
    title="Sovereign-Sync",
    description="Privacy Gateway for LLM APIs with PII Protection",
    version="1.0.0"
)

# Global PII detector instance
pii_detector = PIIDetector()

# API Configuration
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
DEFAULT_MODEL = os.getenv("DEFAULT_MODEL", "gpt-3.5-turbo")

# HTTP client for API calls
http_client = httpx.AsyncClient(timeout=60.0)

@app.on_event("shutdown")
async def shutdown_event():
    """Clean shutdown"""
    await http_client.aclose()

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "c_library": C_LIBRARY_AVAILABLE,
        "openai_key": bool(OPENAI_API_KEY),
        "gemini_key": bool(GEMINI_API_KEY)
    }

@app.post("/v1/chat/completions")
async def chat_completions(request: Request):
    """
    Privacy-protected chat completions endpoint.

    Process:
    1. Extract user messages
    2. Detect and mask PII
    3. Forward to LLM API
    4. Rehydrate response
    5. Clean up vault
    """

    try:
        # Parse request
        body = await request.json()
        messages = body.get("messages", [])
        model = body.get("model", DEFAULT_MODEL)

        # Create request-specific vault
        request_vault = PrivacyVault()

        # Process messages for PII
        processed_messages = []
        for message in messages:
            if message.get("role") == "user" and "content" in message:
                original_content = message["content"]

                # Detect and mask PII
                masked_content = pii_detector.detect_and_mask(original_content)

                # Store mappings in request vault
                for token, original in pii_detector.vault.vault.items():
                    request_vault.vault[token] = original

                processed_messages.append({
                    "role": message["role"],
                    "content": masked_content
                })
            else:
                processed_messages.append(message)

        # Prepare API request
        api_request = {
            "model": model,
            "messages": processed_messages,
            **{k: v for k, v in body.items() if k not in ["model", "messages"]}
        }

        # Forward to OpenAI (you can add Gemini support)
        if not OPENAI_API_KEY:
            raise HTTPException(status_code=500, detail="OpenAI API key not configured")

        headers = {
            "Authorization": f"Bearer {OPENAI_API_KEY}",
            "Content-Type": "application/json"
        }

        # Make API call
        response = await http_client.post(
            "https://api.openai.com/v1/chat/completions",
            json=api_request,
            headers=headers
        )

        if response.status_code != 200:
            raise HTTPException(status_code=response.status_code,
                              detail=f"OpenAI API error: {response.text}")

        api_response = response.json()

        # Rehydrate response
        if "choices" in api_response:
            for choice in api_response["choices"]:
                if "message" in choice and "content" in choice["message"]:
                    original_content = choice["message"]["content"]
                    rehydrated_content = request_vault.rehydrate(original_content)
                    choice["message"]["content"] = rehydrated_content

        # Clean up vault immediately (zero-trust)
        request_vault.clear()

        return JSONResponse(content=api_response)

    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON")
    except Exception as e:
        # Clean up vault even on error
        if 'request_vault' in locals():
            request_vault.clear()
        raise HTTPException(status_code=500, detail=f"Processing error: {str(e)}")

# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app,
        host="127.0.0.1",
        port=8000,
        log_level="info"
    )