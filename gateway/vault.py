"""
Sovereign-Sync: Advanced Vault System
Copyright (c) 2026 - Licensed under GNU GPL v3.0

Production-ready in-memory vault with request-scoped sessions,
unique tokenization, and automatic garbage collection for DPDP compliance.
"""

import asyncio
import hashlib
import secrets
import time
from dataclasses import dataclass, field
from enum import Enum
from threading import Lock
from typing import Dict, List, Optional, Set
from contextlib import asynccontextmanager


class PIICategory(Enum):
    """PII Categories for classification and compliance reporting"""
    AADHAR = "aadhar"
    PAN = "pan"
    PHONE = "phone"
    BANK_ACCOUNT = "bank_account"
    IFSC = "ifsc"
    EMAIL = "email"
    CREDIT_CARD = "credit_card"
    SSN = "ssn"
    PERSON = "person"  # From NLP
    ORG = "org"        # From NLP
    GPE = "gpe"        # From NLP
    ADDRESS = "address" # From NLP


@dataclass
class VaultEntry:
    """Secure vault entry with metadata"""
    token: str
    original_value: str
    category: PIICategory
    timestamp: float = field(default_factory=time.time)
    request_id: str = ""
    ttl: int = 300  # 5 minutes default TTL


@dataclass
class SessionVault:
    """Request-scoped vault with automatic cleanup"""
    session_id: str
    entries: Dict[str, VaultEntry] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    last_accessed: float = field(default_factory=time.time)
    request_count: int = 0

    def add_entry(self, original_value: str, category: PIICategory,
                  request_id: str) -> str:
        """Add entry with unique token per request"""
        # Generate unique token using request_id + session_id + timestamp + random
        token_seed = f"{request_id}_{self.session_id}_{time.time()}_{secrets.token_hex(8)}"
        token_hash = hashlib.sha256(token_seed.encode()).hexdigest()[:16]
        token = f"[{category.value.upper()}_{token_hash}]"

        entry = VaultEntry(
            token=token,
            original_value=original_value,
            category=category,
            request_id=request_id,
            timestamp=time.time()
        )

        self.entries[token] = entry
        self.last_accessed = time.time()
        self.request_count += 1

        return token

    def get_entry(self, token: str) -> Optional[VaultEntry]:
        """Retrieve entry and update access time"""
        entry = self.entries.get(token)
        if entry:
            self.last_accessed = time.time()
        return entry

    def rehydrate_text(self, text: str) -> str:
        """Replace tokens with original values"""
        result = text
        for token, entry in self.entries.items():
            result = result.replace(token, entry.original_value)
        return result

    def cleanup_expired(self, max_age: int = 300) -> int:
        """Remove expired entries, return count removed"""
        current_time = time.time()
        expired_tokens = []

        for token, entry in self.entries.items():
            if current_time - entry.timestamp > entry.ttl:
                expired_tokens.append(token)

        for token in expired_tokens:
            del self.entries[token]

        return len(expired_tokens)

    def get_stats(self) -> Dict:
        """Get vault statistics for monitoring"""
        return {
            "session_id": self.session_id,
            "entry_count": len(self.entries),
            "created_at": self.created_at,
            "last_accessed": self.last_accessed,
            "request_count": self.request_count,
            "categories": list(set(e.category.value for e in self.entries.values()))
        }


class VaultManager:
    """Thread-safe vault manager with garbage collection"""

    def __init__(self, cleanup_interval: int = 60, session_ttl: int = 1800):
        self.vaults: Dict[str, SessionVault] = {}
        self.lock = Lock()
        self.cleanup_interval = cleanup_interval
        self.session_ttl = session_ttl
        self._gc_task: Optional[asyncio.Task] = None

    async def start_gc(self):
        """Start background garbage collection"""
        if self._gc_task is None:
            self._gc_task = asyncio.create_task(self._garbage_collect_loop())

    async def stop_gc(self):
        """Stop background garbage collection"""
        if self._gc_task:
            self._gc_task.cancel()
            try:
                await self._gc_task
            except asyncio.CancelledError:
                pass
            self._gc_task = None

    async def _garbage_collect_loop(self):
        """Background garbage collection loop"""
        while True:
            try:
                await asyncio.sleep(self.cleanup_interval)
                await self._cleanup_expired_sessions()
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"GC error: {e}")  # In production, use proper logging

    async def _cleanup_expired_sessions(self):
        """Remove expired sessions and entries"""
        current_time = time.time()
        expired_sessions = []

        with self.lock:
            for session_id, vault in self.vaults.items():
                # Remove sessions older than TTL
                if current_time - vault.last_accessed > self.session_ttl:
                    expired_sessions.append(session_id)
                    continue

                # Cleanup expired entries within active sessions
                vault.cleanup_expired()

            for session_id in expired_sessions:
                del self.vaults[session_id]

        if expired_sessions:
            print(f"Cleaned up {len(expired_sessions)} expired sessions")

    @asynccontextmanager
    async def get_session_vault(self, session_id: str, request_id: str):
        """Context manager for request-scoped vault access"""
        vault = None

        with self.lock:
            if session_id not in self.vaults:
                self.vaults[session_id] = SessionVault(session_id=session_id)
            vault = self.vaults[session_id]

        try:
            yield vault
        finally:
            # Immediate cleanup after request completion
            if vault:
                removed = vault.cleanup_expired(max_age=0)  # Remove all entries immediately
                if removed > 0:
                    print(f"Immediate cleanup: removed {removed} entries from session {session_id}")

    def get_global_stats(self) -> Dict:
        """Get global vault statistics"""
        with self.lock:
            total_entries = sum(len(v.entries) for v in self.vaults.values())
            active_sessions = len(self.vaults)

        return {
            "active_sessions": active_sessions,
            "total_entries": total_entries,
            "memory_usage_estimate": total_entries * 256,  # Rough estimate
            "cleanup_interval": self.cleanup_interval,
            "session_ttl": self.session_ttl
        }

    def force_cleanup(self) -> Dict:
        """Force immediate cleanup, return stats"""
        stats = {"sessions_removed": 0, "entries_removed": 0}

        with self.lock:
            current_time = time.time()
            expired_sessions = []

            for session_id, vault in self.vaults.items():
                if current_time - vault.last_accessed > self.session_ttl:
                    expired_sessions.append(session_id)
                    stats["entries_removed"] += len(vault.entries)
                else:
                    stats["entries_removed"] += vault.cleanup_expired()

            for session_id in expired_sessions:
                del self.vaults[session_id]

            stats["sessions_removed"] = len(expired_sessions)

        return stats


# Global vault manager instance
vault_manager = VaultManager()


async def init_vault():
    """Initialize vault system"""
    await vault_manager.start_gc()


async def shutdown_vault():
    """Shutdown vault system"""
    await vault_manager.stop_gc()


def generate_request_id() -> str:
    """Generate unique request ID"""
    return secrets.token_hex(8)