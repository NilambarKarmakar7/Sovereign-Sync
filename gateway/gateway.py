"""
Sovereign-Sync: FastAPI Privacy Gateway
Copyright (c) 2026 - Licensed under GNU GPL v3.0

Tier 2 orchestration layer managing request/response lifecycle with
session-based vault system for PII redaction and rehydration.
Enhanced with contextual PII detection using spaCy NER.
"""

import asyncio
import json
import httpx
import logging
import time
import hashlib
import ctypes
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from uuid import uuid4

from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.responses import JSONResponse
from enum import Enum
import uvicorn

# Enhanced vault system
from vault import VaultManager, SessionVault, PIICategory

# spaCy for contextual PII detection
try:
    import spacy
    nlp = spacy.load("en_core_web_sm")  # Load English NER model
    SPACY_AVAILABLE = True
except ImportError:
    nlp = None
    SPACY_AVAILABLE = False
    logging.warning("spaCy not available - contextual PII detection disabled")

# ============================================================================
# CONFIGURATION
# ============================================================================

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# Session configuration
SESSION_TTL_MINUTES = 30
MAX_SESSIONS = 10000
VAULT_CLEANUP_INTERVAL_SECONDS = 300
REQUEST_TIMEOUT_SECONDS = 60
MAX_REQUEST_SIZE = 1024 * 1024  # 1MB

# PII Detection thresholds for fail-safe
MAX_PII_ENTITIES_PER_REQUEST = 10  # Block if more than 10 entities detected
PII_CONFIDENCE_THRESHOLD = 0.7  # Minimum confidence for NER detections

# Upstream API configuration
OPENAI_API_BASE = "https://api.openai.com/v1"
GEMINI_API_BASE = "https://generativelanguage.googleapis.com/v1"


# ============================================================================
# C LIBRARY INTEGRATION
# ============================================================================

class PIIType(Enum):
    """PII type enumeration matching C header"""
    AADHAR = 1
    PAN = 2
    BANK_ACCOUNT = 4
    IFSC = 8
    EMAIL = 16
    PHONE = 32
    SSN = 64
    CREDIT_CARD = 128


class ScannerContext(ctypes.Structure):
    """Opaque C scanner context (implementation in libpii_scanner.so)"""
    pass


# Load PCRE2-based C library
try:
    # For Windows: libpii_scanner.dll
    # For Linux: libpii_scanner.so
    try:
        libscanner = ctypes.CDLL("../lib/libpii_scanner.dll")
    except OSError:
        libscanner = ctypes.CDLL("../lib/libpii_scanner.so")
except OSError as e:
    logger.error(f"Failed to load PII scanner library: {e}")
    logger.warning("PII scanning disabled - running in passthrough mode")
    libscanner = None

# Function signatures
if libscanner:
    libscanner.scanner_init.argtypes = [ctypes.c_uint64]
    libscanner.scanner_init.restype = ctypes.POINTER(ScannerContext)

    libscanner.scanner_redact.argtypes = [ctypes.POINTER(ScannerContext), ctypes.c_char_p, ctypes.c_size_t]
    libscanner.scanner_redact.restype = ctypes.c_char_p

    libscanner.scanner_rehydrate.argtypes = [ctypes.POINTER(ScannerContext), ctypes.c_char_p]
    libscanner.scanner_rehydrate.restype = ctypes.c_char_p

    libscanner.scanner_free.argtypes = [ctypes.POINTER(ScannerContext)]
    libscanner.scanner_free.restype = None


# ============================================================================
# CONTEXTUAL PII DETECTOR
# ============================================================================

class ContextualPIIDetector:
    """
    Uses spaCy NER to detect contextual PII (names, organizations, locations).

    DPDP Compliance (Section 8 - Data Minimization):
    - Only processes text for necessary entity detection
    - High-confidence detections only to avoid false positives
    """

    def __init__(self):
        self.nlp = nlp if SPACY_AVAILABLE else None

    def detect_entities(self, text: str) -> List[Tuple[str, str, float]]:
        """
        Detect named entities in text.

        Returns: List of (entity_text, label, confidence) tuples
        """
        if not self.nlp or not text:
            return []

        doc = self.nlp(text)
        entities = []

        for ent in doc.ents:
            # Filter for PII-relevant entities
            if ent.label_ in ['PERSON', 'ORG', 'GPE', 'LOC']:
                # Convert spaCy confidence to our scale (simplified)
                confidence = min(1.0, getattr(ent, 'confidence', 0.8))
                entities.append((ent.text, ent.label_, confidence))

        return entities

    def should_block_request(self, entities: List[Tuple[str, str, float]]) -> bool:
        """
        Fail-safe logic: Block request if too much PII detected.

        DPDP Compliance (Section 4 - Purpose Limitation):
        - Prevents processing when risk of inadequate protection is high
        """
        high_confidence_entities = [
            ent for ent in entities
            if ent[2] >= PII_CONFIDENCE_THRESHOLD
        ]

        return len(high_confidence_entities) > MAX_PII_ENTITIES_PER_REQUEST


# ============================================================================
# PII SCANNER WRAPPER
# ============================================================================

class PIIScanner:
    """Wrapper around C PCRE2-based PII scanner"""

    def __init__(self, session_id: str):
        self.session_id = session_id
        self.scanner = None

        if libscanner:
            # Convert session_id to uint64 by hashing
            session_hash = int(hashlib.md5(session_id.encode()).hexdigest()[:16], 16)
            self.scanner = libscanner.scanner_init(session_hash)

    def redact(self, text: str) -> str:
        """Redact PII from text"""
        if not self.scanner or not libscanner:
            return text  # Passthrough if C library unavailable

        try:
            text_bytes = text.encode('utf-8')
            redacted_ptr = libscanner.scanner_redact(
                self.scanner,
                text_bytes,
                len(text_bytes)
            )

            if redacted_ptr:
                return ctypes.string_at(redacted_ptr).decode('utf-8', errors='replace')
        except Exception as e:
            logger.error(f"Redaction error: {e}")

        return text

    def rehydrate(self, redacted_text: str) -> str:
        """Restore original PII from tokens"""
        if not self.scanner or not libscanner:
            return redacted_text

        try:
            text_bytes = redacted_text.encode('utf-8')
            rehydrated_ptr = libscanner.scanner_rehydrate(
                self.scanner,
                text_bytes
            )

            if rehydrated_ptr:
                return ctypes.string_at(rehydrated_ptr).decode('utf-8', errors='replace')
        except Exception as e:
            logger.error(f"Rehydration error: {e}")

        return redacted_text

    def cleanup(self):
        """Free C scanner context"""
        if self.scanner and libscanner:
            libscanner.scanner_free(self.scanner)


# ============================================================================
# ENHANCED REQUEST PROCESSOR
# ============================================================================

class RequestProcessor:
    """
    Handles the complete request processing pipeline with both regex and contextual PII detection.
    """

    def __init__(self):
        self.vault_manager = VaultManager()
        self.context_detector = ContextualPIIDetector()

    def process_request(self, request_body: dict, session_id: str) -> Tuple[dict, bool]:
        """
        Process request: detect PII, redact, store in vault.

        Returns: (redacted_body, should_block)
        """
        vault = self.vault_manager.get_vault(session_id)
        if not vault:
            vault = self.vault_manager.create_vault(session_id)

        redacted_body = request_body.copy()
        total_pii_detected = 0

        # Process messages for PII
        if "messages" in redacted_body:
            for message in redacted_body["messages"]:
                if "content" in message and isinstance(message["content"], str):
                    original_content = message["content"]

                    # Step 1: Regex-based redaction (C library)
                    scanner = PIIScanner(session_id)
                    regex_redacted = scanner.redact(original_content)
                    scanner.cleanup()

                    # Step 2: Contextual PII detection (spaCy NER)
                    entities = self.context_detector.detect_entities(regex_redacted)

                    # Step 3: Redact contextual PII and store in vault
                    contextual_redacted = regex_redacted
                    for entity_text, label, confidence in entities:
                        if confidence >= PII_CONFIDENCE_THRESHOLD:
                            # Map spaCy labels to our categories
                            category_map = {
                                'PERSON': PIICategory.PERSON,
                                'ORG': PIICategory.ORG,
                                'GPE': PIICategory.GPE,
                                'LOC': PIICategory.ADDRESS
                            }

                            category = category_map.get(label, PIICategory.UNKNOWN)
                            token = vault.add_entry(entity_text, category, confidence)
                            contextual_redacted = contextual_redacted.replace(entity_text, token)
                            total_pii_detected += 1

                    message["content"] = contextual_redacted

        # Fail-safe check
        should_block = self.context_detector.should_block_request(
            self.context_detector.detect_entities(str(request_body))
        )

        if should_block:
            logger.warning(f"Request blocked due to high PII count: {total_pii_detected} entities")

        return redacted_body, should_block

    def process_response(self, response_body: dict, session_id: str) -> dict:
        """
        Rehydrate response using vault mappings.
        """
        vault = self.vault_manager.get_vault(session_id)
        if not vault:
            return response_body

        rehydrated_body = response_body.copy()

        # Rehydrate messages
        if "choices" in rehydrated_body:
            for choice in rehydrated_body["choices"]:
                if "message" in choice and "content" in choice["message"]:
                    choice["message"]["content"] = vault.rehydrate_text(
                        choice["message"]["content"]
                    )

        return rehydrated_body


# ============================================================================
# FASTAPI APPLICATION
# ============================================================================

app = FastAPI(
    title="Sovereign-Sync",
    description="Privacy Gateway for LLM API Compliance with Contextual PII Detection",
    version="1.0.0"
)

request_processor = RequestProcessor()


@app.on_event("startup")
async def startup_event():
    """Initialize vault cleanup background task"""
    async def cleanup_loop():
        while True:
            await asyncio.sleep(VAULT_CLEANUP_INTERVAL_SECONDS)
            request_processor.vault_manager.periodic_cleanup()

    asyncio.create_task(cleanup_loop())
    logger.info("Sovereign-Sync gateway initialized")


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    stats = request_processor.vault_manager.get_global_stats()
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "spacy_available": SPACY_AVAILABLE,
        "c_library_loaded": libscanner is not None,
        **stats
    }


@app.post("/v1/session/create")
async def create_session() -> dict:
    """Create new privacy session"""
    try:
        session_id = str(uuid4()).replace("-", "")
        request_processor.vault_manager.create_vault(session_id)
        return {
            "session_id": session_id,
            "ttl_minutes": SESSION_TTL_MINUTES,
            "created_at": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"Session creation error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/v1/session/{session_id}/invalidate")
async def invalidate_session(session_id: str):
    """Invalidate and clear session vault"""
    success = request_processor.vault_manager.destroy_vault(session_id)
    if success:
        logger.info(f"Session invalidated: {session_id}")
        return {"status": "invalidated"}

    raise HTTPException(status_code=404, detail="Session not found")


@app.api_route("/v1/chat/completions", methods=["POST"])
async def proxy_chat_completions(request: Request) -> Response:
    """
    Proxy OpenAI-compatible chat completion endpoint with enhanced PII protection.

    DPDP Compliance Flow:
    1. Purpose Limitation: Only process for redaction (Section 4)
    2. Data Minimization: Extract only necessary PII (Section 8)
    3. Consent: Session-based processing (Section 6)
    4. Security: In-memory vault with TTL (Section 10)
    """

    # Get or create session
    session_id = request.headers.get("X-Sovereign-Session-ID")
    if not session_id:
        session_id = str(uuid4()).replace("-", "")
        request_processor.vault_manager.create_vault(session_id)

    try:
        # Read request body
        body_bytes = await request.body()
        if len(body_bytes) > MAX_REQUEST_SIZE:
            raise HTTPException(status_code=413, detail="Request too large")

        request_body = json.loads(body_bytes)

        # Process request: detect and redact PII
        redacted_body, should_block = request_processor.process_request(
            request_body, session_id
        )

        # Fail-safe: Block if too much PII detected
        if should_block:
            raise HTTPException(
                status_code=403,
                detail="Request blocked: High PII content detected. "
                       "Please reduce sensitive information or contact administrator. "
                       "(DPDP Act 2023 Section 4 compliance)"
            )

        # Forward to upstream (mocked for this example)
        upstream_response = await _forward_to_upstream(redacted_body)

        # Rehydrate response with original PII
        rehydrated_response = request_processor.process_response(
            upstream_response, session_id
        )

        return JSONResponse(
            content=rehydrated_response,
            headers={"X-Sovereign-Session-ID": session_id}
        )

    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON")
    except Exception as e:
        logger.error(f"Error processing request: {e}")
        raise HTTPException(status_code=500, detail=str(e))


async def _forward_to_upstream(body: dict) -> dict:
    """
    Forward request to upstream API
    (Mock implementation - replace with actual upstream calls)
    """
    # This would normally make HTTP call to OpenAI/Gemini
    # For demo, returning sample response
    return {
        "id": "chatcmpl-demo",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": body.get("model", "gpt-4"),
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "[Mock response - data redacted during transit]"
                },
                "finish_reason": "stop"
            }
        ],
        "usage": {
            "prompt_tokens": 10,
            "completion_tokens": 10,
            "total_tokens": 20
        }
    }


@app.get("/v1/status/{session_id}")
async def get_session_status(session_id: str) -> dict:
    """Get session status and vault info"""
    vault = request_processor.vault_manager.get_vault(session_id)
    if not vault:
        raise HTTPException(status_code=404, detail="Session not found")

    return vault.get_stats()


# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    uvicorn.run(
        app,
        host="127.0.0.1",
        port=8000,
        log_level="info"
    )