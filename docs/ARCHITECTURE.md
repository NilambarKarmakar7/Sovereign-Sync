# Sovereign-Sync: System Architecture & Design

## Executive Summary

**Sovereign-Sync** is a high-performance privacy gateway designed to intercept LLM API calls and redact personally identifiable information (PII) to ensure compliance with India's Digital Personal Data Protection (DPDP) Act 2023. The system employs a hybrid architecture combining low-latency C/PCRE2 regex filtering with Python FastAPI orchestration.

---

## 1. Architecture Overview

### 1.1 Two-Tier Design

```
┌─────────────────────────────────────────────────────────────────┐
│                     CLIENT APPLICATION                          │
└─────────────────────────────┬───────────────────────────────────┘
                              │
                              ▼
        ┌─────────────────────────────────────────────┐
        │        Tier 2: FastAPI Gateway              │
        │  ┌───────────────────────────────────────┐  │
        │  │  Session Manager (UUID-based)         │  │
        │  │  Request/Response Orchestration       │  │
        │  │  In-Memory Vault (Token ↔ PII)       │  │
        │  │  TTL Management & Cleanup             │  │
        │  └───────────────────────────────────────┘  │
        │                    │                         │
        │                    ▼                         │
        │  ┌───────────────────────────────────────┐  │
        │  │ Tier 1: C/PCRE2 PII Scanner           │  │
        │  │ ┌─────────────────────────────────┐   │  │
        │  │ │ Regex Patterns (Compiled Cache) │   │  │
        │  │ ├─ Aadhar (12 digits)             │   │  │
        │  │ ├─ PAN (10-char: AAAAA9999A)      │   │  │
        │  │ ├─ Bank Account (9-18 digits)     │   │  │
        │  │ ├─ IFSC (11-char code)            │   │  │
        │  │ ├─ Email & Phone                  │   │  │
        │  │ └─ Credit Card & SSN              │   │  │
        │  │ ┌─────────────────────────────────┐   │  │
        │  │ │ Redaction Engine                │   │  │
        │  │ │ - Match & Extract PII           │   │  │
        │  │ │ - Generate Tokens ([PII_TYPE_n])│   │  │
        │  │ │ - Store in Vault                │   │  │
        │  │ └─────────────────────────────────┘   │  │
        │  └───────────────────────────────────────┘  │
        │                    │                         │
        └────────────────────┼─────────────────────────┘
                             │
                      (Redacted Request)
                             │
                             ▼
        ┌─────────────────────────────────────────────┐
        │       Upstream LLM API (OpenAI/Gemini)      │
        │       • No PII visible in logs              │
        │       • No data retention concerns          │
        │       • API audit trails don't expose data  │
        └────────────────────┬────────────────────────┘
                             │
                      (LLM Response)
                             │
                             ▼
        ┌─────────────────────────────────────────────┐
        │  Tier 2: Response Rehydration               │
        │  ┌───────────────────────────────────────┐  │
        │  │ Pattern Matching: [PII_TYPE_n]        │  │
        │  │ Vault Lookup (O(1) hash)              │  │
        │  │ Original Data Restoration              │  │
        │  └───────────────────────────────────────┘  │
        │                    │                         │
        └────────────────────┼─────────────────────────┘
                             │
                      (Rehydrated Response)
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                    CLIENT (PII Visible)                         │
└─────────────────────────────────────────────────────────────────┘
```

### 1.2 Data Flow

1. **Inbound**: Client sends request with PII to Sovereign-Sync
2. **Tier 2 (Python)**: 
   - API endpoint receives request
   - Extracts/creates session ID
   - Routes to Tier 1 scanner
3. **Tier 1 (C/PCRE2)**:
   - Compiles regex patterns (cached after first init)
   - Matches against text
   - Validates matches (format checks)
   - Generates unique tokens ([AADHAR_1000], [PAN_1001], etc.)
4. **Vault Store**:
   - Original PII stored in session-scoped in-memory map
   - Token → Original mapping
   - TTL tracking per entry
5. **Proxy**:
   - Redacted request forwarded to upstream API
   - Upstream never sees unredacted PII
6. **Response Processing**:
   - LLM response arrives with tokens
   - Rehydration function scans for [PII_*] patterns
   - Vault lookup restores original PII
   - Rehydrated response sent to client

---

## 2. Component Details

### 2.1 Tier 1: C/PCRE2 PII Scanner

**Location**: `src/pii_scanner.c`, `include/pii_scanner.h`

**Purpose**: Sub-millisecond PII detection and redaction

**Key Functions**:

| Function | Purpose | Complexity |
|----------|---------|-----------|
| `scanner_init()` | Initialize PCRE2 context, compile regex patterns | O(1) amortized |
| `scanner_redact()` | Scan text, match patterns, generate tokens | O(n) where n = text length |
| `scanner_rehydrate()` | Restore original PII from tokens | O(n) where n = text length |
| `scanner_validate_*()` | Format validation (Aadhar checksum, PAN format) | O(1) |

**Regex Patterns**:

```c
/* Aadhar: 12 consecutive digits with optional spaces/dashes */
\b(\d{4}[\s-]?\d{4}[\s-]?\d{4})\b

/* PAN: AAAAA9999A format */
\b([A-Z]{5}[0-9]{4}[A-Z]{1})\b

/* Bank Account: 9-18 digits */
\b([0-9]{9,18})\b

/* IFSC: 4 letters + 0 + 6 alphanumeric */
\b([A-Z]{4}0[A-Z0-9]{6})\b

/* Phone: +91/0 + 10-digit Indian number */
\b(\+?91|0)?[6-9]\d{9}\b

/* Email: Standard email regex */
\b([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,})\b
```

**Token Generation**:

```
[AADHAR_1000]
[PAN_1001]
[BANK_1002]
[IFSC_1003]
[EMAIL_1004]
[PHONE_1005]
[CC_1006]
[SSN_1007]
```

**Memory Management**:

- Regex patterns compiled once, cached globally (thread-safe init-once pattern)
- Per-session buffer (1MB max)
- Secure wipe on `scanner_free()` (memset sensitive data)
- No malloc for dynamic allocations beyond initial buffer

### 2.2 Tier 2: FastAPI Gateway

**Location**: `gateway/gateway.py`

**Components**:

#### Session Management
- **UUID-based sessions**: 32-character hex IDs
- **TTL**: 30 minutes configurable
- **Background cleanup**: Every 5 minutes, expired sessions cleared
- **Max sessions**: 10,000 (tunable)

#### In-Memory Vault
```python
SessionVault {
    session_id: str
    vault: Dict[token → VaultEntry]
    created_at: datetime
    last_access: datetime
    ttl_minutes: int
}

VaultEntry {
    token: str
    type: str (AADHAR, PAN, etc.)
    timestamp: float
    ttl_seconds: int
}
```

#### Request/Response Lifecycle

**POST /v1/chat/completions**

1. Extract `X-Sovereign-Session-ID` header or create new
2. Validate session (404 if not found)
3. Read request body (max 1MB)
4. JSON parse
5. Recursively redact all string fields in JSON
6. Forward to upstream (OpenAI/Gemini compatible)
7. Recursively rehydrate response
8. Return with session ID header

#### API Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/health` | GET | Health check + session count |
| `/v1/session/create` | POST | Create new session |
| `/v1/session/{id}/invalidate` | POST | Clear & destroy session |
| `/v1/chat/completions` | POST | Main proxy endpoint |
| `/v1/status/{id}` | GET | Session status |

### 2.3 C-to-Python Integration

**Mechanism**: ctypes library wrapping C shared object

```python
# Load compiled .dll or .so
libscanner = ctypes.CDLL("./lib/libpii_scanner.dll")

# Function signatures
libscanner.scanner_init.argtypes = [c_uint64]
libscanner.scanner_init.restype = POINTER(ScannerContext)

libscanner.scanner_redact.argtypes = [
    POINTER(ScannerContext), c_char_p, c_size_t
]
libscanner.scanner_redact.restype = c_char_p

# Usage
scanner = libscanner.scanner_init(session_hash)
redacted = libscanner.scanner_redact(scanner, text_bytes, len(text_bytes))
```

**Fallback**: If C library unavailable, gateway operates in passthrough mode (no redaction, logs warning).

---

## 3. Performance Characteristics

### Latency Budget

| Component | Target | Notes |
|-----------|--------|-------|
| **Tier 1 (C Scanner)** | < 1ms | PCRE2 JIT compiled, cached patterns |
| **Tier 2 (FastAPI)** | < 10ms | Session lookup O(1), JSON parsing |
| **Round-trip** | < 50ms | Assuming network calls to upstream |

### Scalability

- **Sessions**: Linear memory with number of sessions (estimated 100KB/session)
- **Redactions/session**: Up to 1000 PII tokens
- **Concurrent requests**: Limited by FastAPI worker count (default 4)
- **Request size**: Capped at 1MB (configurable)

---

## 4. Security & Privacy

### Zero-Trust Principles

1. **No Disk Writes**: All data in-memory only
   - Session vaults: RAM-backed
   - Original PII: Stored only in vault, never logged
   - Logs: Redacted before output

2. **No External Logging**
   - Error conditions logged locally only
   - No traces sent to external services
   - Session IDs not logged with PII

3. **Secure Cleanup**
   ```c
   /* Overwrite sensitive memory before freeing */
   memset(scanner->vault[i].original_data, 0, scanner->vault[i].data_len);
   free(scanner->vault[i].original_data);
   ```

4. **Session Isolation**
   - Each session gets independent vault
   - Tokens generated with atomic counter (no collisions)
   - Cross-session vault access impossible

### Threat Model

| Threat | Mitigation |
|--------|-----------|
| **Memory dumps** | Data only in-memory during session, cleared on logout |
| **Log analysis** | No PII in logs, only tokens |
| **Process inspection** | Vault entries overwritten before deallocation |
| **Session hijacking** | Random 256-bit session IDs (uuid4) |
| **Regex DoS** | PCRE2 JIT + fixed input size limit (1MB) |

---

## 5. Compliance with DPDP Act 2023

(See DPDP_COMPLIANCE.md for detailed analysis)

**Key Sections**:

- **Section 4 (Purpose Limitation)**: Data used only for redaction/restoration
- **Section 8 (Data Minimization)**: Only necessary PII extracted and stored temporarily
- **Section 6 (Consent)**: User controls session via explicit session creation
- **Section 10 (Data Security)**: In-memory storage, secure cleanup, no external logging

---

## 6. Building & Deployment

### Prerequisites

- **C Compiler**: GCC 9+ or Clang
- **CMake**: 3.10+
- **PCRE2**: libpcre2-dev (development headers)
- **Python**: 3.8+

### Build Steps

```bash
# Linux/macOS
mkdir build
cd build
cmake ..
make

# Windows (MinGW)
mkdir build
cd build
cmake -G "MinGW Makefiles" ..
mingw32-make
```

### Run Gateway

```bash
# Install Python dependencies
pip install -r requirements.txt

# Run FastAPI
python gateway/gateway.py
```

### Testing

```bash
# Build & run C tests
cd build
ctest
```

---

## 7. Configuration

See `gateway.py` configuration section:

```python
SESSION_TTL_MINUTES = 30
MAX_SESSIONS = 10000
VAULT_CLEANUP_INTERVAL_SECONDS = 300
REQUEST_TIMEOUT_SECONDS = 60
MAX_REQUEST_SIZE = 1024 * 1024  # 1MB
```

---

## 8. Future Enhancements

1. **GPU Acceleration**: Use CuPCRE2 for ultra-large payloads
2. **Distributed Sessions**: Redis-backed vault for multi-instance deployments
3. **Advanced Analytics**: Redacted usage metrics (token counts, patterns)
4. **Custom Pattern Library**: User-defined regex patterns per deployment
5. **Differential Privacy**: Add noise to redaction counts for privacy
