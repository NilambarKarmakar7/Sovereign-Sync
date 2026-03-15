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
from typing import Dict, Optional, List, AsyncGenerator
from uuid import uuid4

import httpx
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse, StreamingResponse
from dotenv import load_dotenv
import ctypes

# Import thread-safe vault
from vault import get_global_vault, create_session, clear_session

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
        self.vault = get_global_vault()

    def process_text(self, text: str, session_id: str) -> tuple[str, int]:
        """
        Bridge logic: Detect PII with C module, tokenize with thread-safe vault

        Args:
            text: Text to process
            session_id: Session identifier for vault isolation

        Returns: (masked_text, pii_count)
        """
        # Detect PII using C module
        pii_matches = self.c_bridge.detect_pii(text)

        # Sort matches by position (important for replacement)
        pii_matches.sort(key=lambda x: x['start_pos'], reverse=True)

        # Replace PII with tokens (reverse order to maintain positions)
        masked_text = text
        pii_count = 0

        for match in pii_matches:
            try:
                token, _ = self.vault.tokenize(match['text'], match['pii_type'], session_id)
                start, end = match['start_pos'], match['end_pos']
                masked_text = masked_text[:start] + token + masked_text[end:]
                pii_count += 1
            except Exception as e:
                print(f"⚠ Tokenization error for {match['pii_type']}: {e}")
                # Continue processing other matches

        return masked_text, pii_count

    def rehydrate_text(self, text: str, session_id: str) -> str:
        """Rehydrate text using vault mappings"""
        return self.vault.rehydrate(text, session_id)

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
LLM_API_BASE_URL = os.getenv("LLM_API_BASE_URL", "https://api.openai.com/v1")
LLM_CHAT_PATH = os.getenv("LLM_CHAT_PATH", "/chat/completions")
DEFAULT_MODEL = os.getenv("DEFAULT_MODEL", "gpt-3.5-turbo")
LLM_REQUEST_TIMEOUT = float(os.getenv("LLM_REQUEST_TIMEOUT", "60"))

# HTTP client for API calls (reused for streaming)
http_client = httpx.AsyncClient(base_url=LLM_API_BASE_URL, timeout=httpx.Timeout(LLM_REQUEST_TIMEOUT))

@app.on_event("shutdown")
async def shutdown_event():
    """Clean shutdown"""
    await http_client.aclose()
    pii_processor.cleanup()

def dpdp_error_response(detail: str, status_code: int = 500):
    """Return a DPDP-compliant error response."""
    return JSONResponse(
        status_code=status_code,
        content={
            "error": detail,
            "dpdp_compliance": {
                "sections": ["4", "8", "10"],
                "note": "Request blocked to protect personal data and ensure DPDP compliance."
            }
        }
    )


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "c_bridge_initialized": pii_processor.c_bridge.initialized,
        "llm_api_base_url": LLM_API_BASE_URL,
        "openai_key": bool(OPENAI_API_KEY)
    }


@app.post("/v1/session/create")
async def create_session_endpoint():
    """Create a new session ID for explicit client session control."""
    session_id = create_session()
    ttl = int(os.getenv("SESSION_TTL", "3600"))
    return {"session_id": session_id, "ttl_seconds": ttl}


@app.get("/v1/status/{session_id}")
async def session_status(session_id: str):
    """Get vault session statistics."""
    stats = get_global_vault().get_session_stats(session_id)
    if stats.get("counter", 0) == 0 and stats.get("tokens", 0) == 0:
        return dpdp_error_response("Session not found", status_code=404)
    return {"session_id": session_id, "stats": stats}

@app.post("/v1/chat/completions")
async def chat_completions(request: Request):
    """
    Privacy-protected chat completions with complete rehydration loop.

    Supports both regular and streaming responses with fail-safe mode.

    Process:
    1. Extract user messages
    2. Detect PII with C module, tokenize with thread-safe vault
    3. Send anonymized prompt to LLM
    4. Rehydrate response with original PII
    5. Clean up vault (zero-trust)
    """

    session_id = None
    try:
        # Parse request
        body = await request.json()
        messages = body.get("messages", [])
        model = body.get("model", DEFAULT_MODEL)
        stream = body.get("stream", False)

        if not OPENAI_API_KEY:
            return dpdp_error_response(
                "LLM API key not configured. Set OPENAI_API_KEY in the .env file.",
                status_code=500
            )

        # Determine session ID (support client-provided session for explicit reuse)
        header_session_id = request.headers.get("X-Sovereign-Session-ID")
        if header_session_id:
            stats = get_global_vault().get_session_stats(header_session_id)
            if stats.get("counter", 0) > 0:
                session_id = header_session_id
            else:
                session_id = create_session()
        else:
            session_id = create_session()

        # Process messages for PII with fail-safe mode
        processed_messages = []
        total_pii_detected = 0
        processing_errors = []

        for message in messages:
            if message.get("role") == "user" and "content" in message:
                original_content = message["content"]

                try:
                    # Bridge logic: C detection + Python tokenization
                    masked_content, pii_count = pii_processor.process_text(original_content, session_id)
                    processed_messages.append({
                        "role": message["role"],
                        "content": masked_content
                    })
                    total_pii_detected += pii_count

                except Exception as e:
                    # Fail-safe mode: Block request if PII processing fails
                    error_msg = f"PII processing failed for message: {str(e)}"
                    processing_errors.append(error_msg)
                    print(f"⚠ {error_msg}")

                    # Clean up session
                    if session_id:
                        clear_session(session_id)

                    return dpdp_error_response(
                        "PII processing failed - request blocked for privacy protection.",
                        status_code=400
                    )
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

        # Handle streaming vs regular responses
        if stream:
            response_session_id = header_session_id or session_id
            return StreamingResponse(
                stream_openai_response(api_request, headers, session_id),
                media_type="text/plain",
                headers={"X-Sovereign-Session-ID": response_session_id}
            )
        else:
            # Regular response
            response = await http_client.post(
                LLM_CHAT_PATH,
                json=api_request,
                headers=headers
            )

            if response.status_code != 200:
                # Return a clean DPDP-compliant error instead of raw traceback
                error_msg = f"Upstream LLM error (status {response.status_code})"
                return dpdp_error_response(error_msg, status_code=response.status_code)

            api_response = response.json()

            # Rehydrate response using vault
            if "choices" in api_response:
                for choice in api_response["choices"]:
                    if "message" in choice and "content" in choice["message"]:
                        original_content = choice["message"]["content"]
                        rehydrated_content = pii_processor.rehydrate_text(original_content, session_id)
                        choice["message"]["content"] = rehydrated_content

            # Response should include the session used (if any)
            response_session_id = header_session_id or session_id

            # Zero-trust cleanup: Clear vault immediately
            clear_session(session_id)
            session_id = None

            return JSONResponse(content=api_response, headers={"X-Sovereign-Session-ID": response_session_id})

    except json.JSONDecodeError:
        return dpdp_error_response("Invalid JSON payload", status_code=400)
    except Exception as e:
        # Clean up vault even on error
        if session_id:
            clear_session(session_id)
        # Do not expose internal exception details
        return dpdp_error_response("Internal server error", status_code=500)


async def stream_openai_response(api_request: dict, headers: dict, session_id: str) -> AsyncGenerator[str, None]:
    """
    Stream OpenAI response with real-time PII rehydration.

    Args:
        api_request: The API request payload
        headers: HTTP headers for the request
        session_id: Session ID for vault access
    """
    try:
        async with http_client.stream(
            "POST",
            LLM_CHAT_PATH,
            json=api_request,
            headers=headers
        ) as response:
            if response.status_code != 200:
                error_text = await response.aread()
                payload = {
                    "error": f"Upstream LLM error (status {response.status_code})",
                    "dpdp_compliance": {
                        "sections": ["4", "8", "10"],
                        "note": "Request blocked to protect personal data."
                    }
                }
                yield f"data: {json.dumps(payload)}\n\n"
                return

            buffer = ""
            async for line in response.aiter_lines():
                if line.startswith("data: "):
                    data = line[6:]  # Remove "data: " prefix

                    if data == "[DONE]":
                        yield f"data: [DONE]\n\n"
                        break

                    try:
                        chunk = json.loads(data)
                        if "choices" in chunk and chunk["choices"]:
                            choice = chunk["choices"][0]
                            if "delta" in choice and "content" in choice["delta"]:
                                content = choice["delta"]["content"]
                                buffer += content

                                # Rehydrate content in real-time
                                rehydrated_content = pii_processor.rehydrate_text(content, session_id)

                                # Update the chunk with rehydrated content
                                chunk["choices"][0]["delta"]["content"] = rehydrated_content
                                yield f"data: {json.dumps(chunk)}\n\n"

                    except json.JSONDecodeError:
                        continue

    finally:
        # Clean up session after streaming
        clear_session(session_id)

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