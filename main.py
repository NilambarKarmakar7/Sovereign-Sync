"""
Sovereign-Sync: Privacy Gateway with C-Python Bridge
Copyright (c) 2026 - Licensed under GNU GPL v3.0

Complete request-response lifecycle with C-based PII detection,
Python tokenization, and rehydration loop.
"""

import asyncio
import json
import os
import logging
from typing import Dict, Optional, List
from uuid import uuid4

import httpx
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from dotenv import load_dotenv
import ctypes

# Load environment variables
load_dotenv()

# ============================================================================
# C-PYTHON BRIDGE STRUCTURES
# ============================================================================

class PII_MATCH(ctypes.Structure):
    """C structure for PII detection results"""
    _fields_ = [
        ("text", ctypes.c_char_p),
        ("start_pos", ctypes.c_int),
        ("end_pos", ctypes.c_int),
        ("pii_type", ctypes.c_int)
    ]

# ============================================================================
# PRIVACY VAULT
# ============================================================================

class PrivacyVault:
    """In-memory vault for PII tokenization and rehydration"""

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
# C MODULE INTEGRATION
# ============================================================================

class CPIIBridge:
    """Bridge between Python and C PII detection module"""

    def __init__(self):
        self.lib = None
        self.initialized = False

        # Try to load the C library
        try:
            lib_paths = [
                os.path.join(os.path.dirname(__file__), 'libpii_filter.so'),
                os.path.join(os.path.dirname(__file__), 'libpii_filter.dll'),
                os.path.join(os.path.dirname(__file__), 'build', 'libpii_filter.so'),
                os.path.join(os.path.dirname(__file__), 'build', 'libpii_filter.dll'),
            ]

            for lib_path in lib_paths:
                if os.path.exists(lib_path):
                    self.lib = ctypes.CDLL(lib_path)
                    break

            if self.lib:
                # Define function signatures
                self.lib.pii_scanner_init.argtypes = []
                self.lib.pii_scanner_init.restype = ctypes.c_int

                self.lib.pii_scanner_cleanup.argtypes = []
                self.lib.pii_scanner_cleanup.restype = None

                self.lib.pii_scanner_detect.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_int)]
                self.lib.pii_scanner_detect.restype = ctypes.POINTER(PII_MATCH)

                self.lib.pii_scanner_free_matches.argtypes = [ctypes.POINTER(PII_MATCH), ctypes.c_int]
                self.lib.pii_scanner_free_matches.restype = None

                self.lib.pii_type_name.argtypes = [ctypes.c_int]
                self.lib.pii_type_name.restype = ctypes.c_char_p

                # Initialize the C module
                if self.lib.pii_scanner_init():
                    self.initialized = True
                    print("✓ C PII scanner initialized successfully")
                else:
                    print("⚠ C PII scanner initialization failed")
            else:
                print("⚠ C PII scanner library not found - using fallback")

        except Exception as e:
            print(f"⚠ Failed to load C library: {e}")

    def detect_pii(self, text: str) -> List[Dict]:
        """Detect PII using C module and return structured results"""
        if not self.initialized or not self.lib:
            return self._fallback_detection(text)

        try:
            # Use memory-safe string buffer
            text_buffer = ctypes.create_string_buffer(text.encode('utf-8'))
            num_matches = ctypes.c_int(0)

            # Call C function
            matches_ptr = self.lib.pii_scanner_detect(text_buffer, ctypes.byref(num_matches))

            if not matches_ptr or num_matches.value == 0:
                return []

            # Convert C array to Python list
            matches = []
            for i in range(num_matches.value):
                match = matches_ptr[i]
                pii_type_name = self.lib.pii_type_name(match.pii_type).decode('utf-8')

                matches.append({
                    'text': match.text.decode('utf-8') if match.text else '',
                    'start_pos': match.start_pos,
                    'end_pos': match.end_pos,
                    'pii_type': pii_type_name
                })

            # Free C memory
            self.lib.pii_scanner_free_matches(matches_ptr, num_matches)

            return matches

        except Exception as e:
            print(f"⚠ C PII detection error: {e}")
            return self._fallback_detection(text)

    def _fallback_detection(self, text: str) -> List[Dict]:
        """Fallback PII detection using Python regex"""
        import re

        matches = []

        # Aadhar pattern
        for match in re.finditer(r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}\b', text):
            matches.append({
                'text': match.group(),
                'start_pos': match.start(),
                'end_pos': match.end(),
                'pii_type': 'AADHAR'
            })

        # PAN pattern
        for match in re.finditer(r'\b[A-Z]{5}\d{4}[A-Z]\b', text):
            matches.append({
                'text': match.group(),
                'start_pos': match.start(),
                'end_pos': match.end(),
                'pii_type': 'PAN'
            })

        # Phone pattern
        for match in re.finditer(r'\b(?:\+?91|0)?[6-9]\d{9}\b', text):
            matches.append({
                'text': match.group(),
                'start_pos': match.start(),
                'end_pos': match.end(),
                'pii_type': 'PHONE'
            })

        return matches

    def cleanup(self):
        """Clean up C module resources"""
        if self.lib and self.initialized:
            self.lib.pii_scanner_cleanup()

# ============================================================================
# PII PROCESSOR WITH BRIDGE LOGIC
# ============================================================================

class PIIProcessor:
    """Complete PII processing with C-Python bridge"""

    def __init__(self):
        self.c_bridge = CPIIBridge()

    def process_text(self, text: str) -> tuple[str, PrivacyVault]:
        """
        Bridge logic: Detect PII with C module, tokenize with Python vault

        Returns: (masked_text, vault_with_mappings)
        """
        vault = PrivacyVault()

        # Detect PII using C module
        pii_matches = self.c_bridge.detect_pii(text)

        # Sort matches by position (important for replacement)
        pii_matches.sort(key=lambda x: x['start_pos'], reverse=True)

        # Replace PII with tokens (reverse order to maintain positions)
        masked_text = text
        for match in pii_matches:
            token, _ = vault.tokenize(match['text'], match['pii_type'])
            start, end = match['start_pos'], match['end_pos']
            masked_text = masked_text[:start] + token + masked_text[end:]

        return masked_text, vault

    def rehydrate_text(self, text: str, vault: PrivacyVault) -> str:
        """Rehydrate text using vault mappings"""
        return vault.rehydrate(text)

    def cleanup(self):
        """Clean up resources"""
        self.c_bridge.cleanup()

# ============================================================================
# FASTAPI APPLICATION
# ============================================================================

app = FastAPI(
    title="Sovereign-Sync",
    description="Privacy Gateway with C-Python PII Detection Bridge",
    version="1.0.0"
)

# Global PII processor
pii_processor = PIIProcessor()

# API Configuration
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
DEFAULT_MODEL = os.getenv("DEFAULT_MODEL", "gpt-3.5-turbo")

# HTTP client for API calls
http_client = httpx.AsyncClient(timeout=60.0)

@app.on_event("shutdown")
async def shutdown_event():
    """Clean shutdown"""
    await http_client.aclose()
    pii_processor.cleanup()

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "c_bridge_initialized": pii_processor.c_bridge.initialized,
        "openai_key": bool(OPENAI_API_KEY)
    }

@app.post("/v1/chat/completions")
async def chat_completions(request: Request):
    """
    Privacy-protected chat completions with complete rehydration loop.

    Process:
    1. Extract user messages
    2. Detect PII with C module, tokenize with Python vault
    3. Send anonymized prompt to LLM
    4. Rehydrate response with original PII
    5. Clean up vault (zero-trust)
    """

    try:
        # Parse request
        body = await request.json()
        messages = body.get("messages", [])
        model = body.get("model", DEFAULT_MODEL)

        if not OPENAI_API_KEY:
            raise HTTPException(status_code=500, detail="OpenAI API key not configured")

        # Create request-specific vault for this session
        request_vault = PrivacyVault()

        # Process messages for PII
        processed_messages = []
        total_pii_detected = 0

        for message in messages:
            if message.get("role") == "user" and "content" in message:
                original_content = message["content"]

                # Bridge logic: C detection + Python tokenization
                masked_content, message_vault = pii_processor.process_text(original_content)

                # Merge vault mappings into request vault
                for token, original in message_vault.vault.items():
                    request_vault.vault[token] = original

                processed_messages.append({
                    "role": message["role"],
                    "content": masked_content
                })

                total_pii_detected += len(message_vault.vault)

            else:
                processed_messages.append(message)

        # Prepare API request
        api_request = {
            "model": model,
            "messages": processed_messages,
            **{k: v for k, v in body.items() if k not in ["model", "messages"]}
        }

        # Forward to OpenAI
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

        # Rehydrate response using vault
        if "choices" in api_response:
            for choice in api_response["choices"]:
                if "message" in choice and "content" in choice["message"]:
                    original_content = choice["message"]["content"]
                    rehydrated_content = pii_processor.rehydrate_text(original_content, request_vault)
                    choice["message"]["content"] = rehydrated_content

        # Zero-trust cleanup: Clear vault immediately
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