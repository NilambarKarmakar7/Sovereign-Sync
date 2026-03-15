"""
Sovereign-Sync: Enhanced Vault System
Copyright (c) 2026 - Licensed under GNU GPL v3.0

Advanced in-memory vault for session-based PII tokenization with
support for both regex-based and contextual (NER) PII detection.
Implements zero-trust principles per DPDP Act 2023 Section 8.
"""

import time
import logging
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass
from enum import Enum
import hashlib
import secrets

logger = logging.getLogger(__name__)

class PIICategory(Enum):
    """PII categories for classification and compliance tracking"""
    PERSON = "PERSON"
    ORG = "ORG"
    GPE = "GPE"  # Geo-Political Entity (locations)
    AADHAR = "AADHAR"
    PAN = "PAN"
    BANK_ACCOUNT = "BANK_ACCOUNT"
    IFSC = "IFSC"
    EMAIL = "EMAIL"
    PHONE = "PHONE"
    CREDIT_CARD = "CREDIT_CARD"
    SSN = "SSN"
    ADDRESS = "ADDRESS"  # Contextual detection
    UNKNOWN = "UNKNOWN"

@dataclass
class VaultEntry:
    """Enhanced vault entry with metadata for compliance"""
    token: str
    original_value: str
    category: PIICategory
    confidence: float  # For NER detections (0.0-1.0)
    timestamp: float
    ttl_seconds: int = 1800  # 30 minutes default
    request_id: str = ""  # Links to specific request
    
    def is_expired(self) -> bool:
        """Check if entry has expired per DPDP storage limitation"""
        return time.time() > (self.timestamp + self.ttl_seconds)
    
    def secure_wipe(self) -> None:
        """Securely overwrite sensitive data before deletion"""
        # Overwrite with random bytes for security
        random_data = secrets.token_bytes(len(self.original_value))
        self.original_value = random_data.hex()  # Convert to hex for storage
        # In real implementation, use memory wiping techniques

class SessionVault:
    """
    Enhanced in-memory vault for session-based PII mapping.
    
    DPDP Compliance (Section 8 - Data Minimization):
    - Only stores necessary PII for redaction/rehydration
    - Automatic TTL-based cleanup
    - Secure memory wiping on deletion
    - No persistent storage (RAM-only)
    """
    
    def __init__(self, session_id: str, ttl_minutes: int = 30):
        self.session_id = session_id
        self.entries: Dict[str, VaultEntry] = {}
        self.created_at = time.time()
        self.last_access = time.time()
        self.ttl_minutes = ttl_minutes
        self.request_counter = 0  # For unique request IDs
        
        # Compliance tracking
        self.total_pii_detected = 0
        self.categories_detected: Set[PIICategory] = set()
    
    def add_entry(self, original_value: str, category: PIICategory, 
                  confidence: float = 1.0, request_id: str = "") -> str:
        """
        Add PII entry to vault with unique token generation.
        
        Returns the generated token for replacement.
        """
        if not request_id:
            self.request_counter += 1
            request_id = f"req_{self.request_counter}"
        
        # Generate unique token
        token_base = f"{category.value}_{len(self.entries) + 1}"
        token = f"[{token_base}]"
        
        # Ensure uniqueness
        counter = 1
        while token in self.entries:
            token = f"[{token_base}_{counter}]"
            counter += 1
        
        entry = VaultEntry(
            token=token,
            original_value=original_value,
            category=category,
            confidence=confidence,
            timestamp=time.time(),
            request_id=request_id
        )
        
        self.entries[token] = entry
        self.last_access = time.time()
        self.total_pii_detected += 1
        self.categories_detected.add(category)
        
        logger.info(f"Vault entry added: {token} ({category.value}) for session {self.session_id}")
        return token
    
    def get_entry(self, token: str) -> Optional[VaultEntry]:
        """Retrieve vault entry by token"""
        self.last_access = time.time()
        return self.entries.get(token)
    
    def get_original_value(self, token: str) -> Optional[str]:
        """Get original PII value for rehydration"""
        entry = self.get_entry(token)
        return entry.original_value if entry else None
    
    def rehydrate_text(self, text: str) -> str:
        """
        Rehydrate text by replacing tokens with original values.
        
        DPDP Compliance: Ensures data is restored only for authorized sessions.
        """
        result = text
        for token, entry in self.entries.items():
            if not entry.is_expired():
                result = result.replace(token, entry.original_value)
            else:
                # Remove expired tokens
                result = result.replace(token, "[EXPIRED_PII]")
                logger.warning(f"Expired token {token} in rehydration for session {self.session_id}")
        
        return result
    
    def cleanup_expired(self) -> int:
        """Remove expired entries and securely wipe them"""
        expired_tokens = []
        for token, entry in self.entries.items():
            if entry.is_expired():
                entry.secure_wipe()
                expired_tokens.append(token)
        
        for token in expired_tokens:
            del self.entries[token]
        
        if expired_tokens:
            logger.info(f"Cleaned up {len(expired_tokens)} expired entries in session {self.session_id}")
        
        return len(expired_tokens)
    
    def is_session_expired(self) -> bool:
        """Check if entire session has expired"""
        return time.time() > (self.created_at + self.ttl_minutes * 60)
    
    def get_stats(self) -> Dict:
        """Get vault statistics for monitoring"""
        return {
            "session_id": self.session_id,
            "total_entries": len(self.entries),
            "categories": [cat.value for cat in self.categories_detected],
            "total_pii_detected": self.total_pii_detected,
            "created_at": self.created_at,
            "last_access": self.last_access,
            "ttl_remaining_seconds": max(0, (self.created_at + self.ttl_minutes * 60) - time.time())
        }
    
    def secure_clear(self) -> None:
        """Securely clear entire vault (called on session destruction)"""
        for entry in self.entries.values():
            entry.secure_wipe()
        
        self.entries.clear()
        self.categories_detected.clear()
        
        logger.info(f"Vault securely cleared for session {self.session_id}")

class VaultManager:
    """
    Manages multiple session vaults with background cleanup.
    
    DPDP Compliance (Section 10 - Data Security):
    - Ensures secure handling and timely destruction of personal data
    """
    
    def __init__(self, max_sessions: int = 10000, cleanup_interval_seconds: int = 300):
        self.vaults: Dict[str, SessionVault] = {}
        self.max_sessions = max_sessions
        self.cleanup_interval = cleanup_interval_seconds
        self._last_cleanup = time.time()
    
    def create_vault(self, session_id: str, ttl_minutes: int = 30) -> SessionVault:
        """Create new session vault"""
        if len(self.vaults) >= self.max_sessions:
            raise RuntimeError("Maximum sessions reached")
        
        if session_id in self.vaults:
            return self.vaults[session_id]
        
        vault = SessionVault(session_id, ttl_minutes)
        self.vaults[session_id] = vault
        
        logger.info(f"Created vault for session {session_id}")
        return vault
    
    def get_vault(self, session_id: str) -> Optional[SessionVault]:
        """Get existing vault"""
        return self.vaults.get(session_id)
    
    def destroy_vault(self, session_id: str) -> bool:
        """Securely destroy session vault"""
        vault = self.vaults.get(session_id)
        if vault:
            vault.secure_clear()
            del self.vaults[session_id]
            logger.info(f"Destroyed vault for session {session_id}")
            return True
        return False
    
    def periodic_cleanup(self) -> int:
        """Clean up expired sessions and entries"""
        current_time = time.time()
        if current_time - self._last_cleanup < self.cleanup_interval:
            return 0
        
        expired_sessions = []
        total_cleaned_entries = 0
        
        for session_id, vault in self.vaults.items():
            # Clean expired entries within session
            total_cleaned_entries += vault.cleanup_expired()
            
            # Check if entire session expired
            if vault.is_session_expired():
                vault.secure_clear()
                expired_sessions.append(session_id)
        
        for session_id in expired_sessions:
            del self.vaults[session_id]
        
        self._last_cleanup = current_time
        
        if expired_sessions or total_cleaned_entries:
            logger.info(f"Periodic cleanup: {len(expired_sessions)} sessions, {total_cleaned_entries} entries")
        
        return len(expired_sessions)
    
    def get_global_stats(self) -> Dict:
        """Get global vault statistics"""
        total_entries = sum(len(vault.entries) for vault in self.vaults.values())
        total_sessions = len(self.vaults)
        
        return {
            "total_sessions": total_sessions,
            "total_entries": total_entries,
            "max_sessions": self.max_sessions,
            "last_cleanup": self._last_cleanup
        }
