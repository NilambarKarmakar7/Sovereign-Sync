"""
Sovereign-Sync: Thread-Safe Privacy Vault
Copyright (c) 2026 - Licensed under GNU GPL v3.0

Thread-safe in-memory vault for PII tokenization and rehydration.
Uses session IDs to prevent data mixing between concurrent requests.
"""

import os
import threading
from typing import Dict, Optional
from uuid import uuid4
import time


class PrivacyVault:
    """
    Thread-safe in-memory vault for PII tokenization and rehydration.

    Uses session IDs to isolate data between concurrent requests and
    threading.Lock to prevent race conditions.
    """

    def __init__(self):
        self._vaults: Dict[str, Dict[str, str]] = {}
        self._token_counters: Dict[str, int] = {}
        self._session_meta: Dict[str, float] = {}
        self._lock = threading.RLock()  # Reentrant lock for thread safety
        self._session_timeout = int(os.getenv("SESSION_TTL", "3600"))

    def create_session(self) -> str:
        """
        Create a new session with unique ID.

        Returns:
            str: Unique session identifier
        """
        session_id = str(uuid4())
        with self._lock:
            self._vaults[session_id] = {}
            self._token_counters[session_id] = 1000
            self._session_meta[session_id] = time.time()
        # Clean up expired sessions opportunistically
        self.cleanup_expired_sessions()
        return session_id

    def tokenize(self, text: str, pii_type: str, session_id: str) -> tuple[str, str]:
        """
        Replace PII with token and store mapping for session.

        Args:
            text: The PII text to tokenize
            pii_type: Type of PII (AADHAR, PAN, etc.)
            session_id: Session identifier for isolation

        Returns:
            tuple: (token, original_text)
        """
        with self._lock:
            if session_id not in self._vaults:
                raise ValueError(f"Invalid session ID: {session_id}")

            token = f"[{pii_type}_{self._token_counters[session_id]}]"
            self._token_counters[session_id] += 1

            self._vaults[session_id][token] = text
            return token, text

    def rehydrate(self, text: str, session_id: str) -> str:
        """
        Replace tokens with original PII for session.

        Args:
            text: Text containing tokens to replace
            session_id: Session identifier

        Returns:
            str: Text with tokens replaced by original PII
        """
        with self._lock:
            if session_id not in self._vaults:
                return text  # Return unchanged if session doesn't exist

            vault = self._vaults[session_id]
            result = text
            for token, original in vault.items():
                result = result.replace(token, original)
            return result

    def clear_session(self, session_id: str):
        """
        Securely clear vault data for a session.

        Args:
            session_id: Session identifier to clear
        """
        with self._lock:
            if session_id in self._vaults:
                self._vaults[session_id].clear()
                del self._vaults[session_id]
            if session_id in self._token_counters:
                del self._token_counters[session_id]
            if session_id in self._session_meta:
                del self._session_meta[session_id]

    def get_session_stats(self, session_id: str) -> Dict[str, int]:
        """
        Get statistics for a session.

        Args:
            session_id: Session identifier

        Returns:
            dict: Session statistics
        """
        # Opportunistically clean up expired sessions
        self.cleanup_expired_sessions()

        with self._lock:
            if session_id not in self._vaults:
                return {"tokens": 0, "counter": 0, "age_seconds": None}

            age = None
            if session_id in self._session_meta:
                age = time.time() - self._session_meta[session_id]

            return {
                "tokens": len(self._vaults[session_id]),
                "counter": self._token_counters.get(session_id, 0),
                "age_seconds": age
            }

    def cleanup_expired_sessions(self):
        """Clean up expired sessions based on TTL."""
        now = time.time()
        expired = []

        with self._lock:
            for session_id, created_at in list(self._session_meta.items()):
                if now - created_at > self._session_timeout:
                    expired.append(session_id)

            for session_id in expired:
                self.clear_session(session_id)

    def get_total_sessions(self) -> int:
        """Get total number of active sessions."""
        with self._lock:
            return len(self._vaults)


# Global vault instance for application-wide use
_global_vault = PrivacyVault()


def get_global_vault() -> PrivacyVault:
    """Get the global vault instance."""
    return _global_vault


def create_session() -> str:
    """Create a new session in the global vault."""
    return _global_vault.create_session()


def clear_session(session_id: str):
    """Clear a session in the global vault."""
    _global_vault.clear_session(session_id)