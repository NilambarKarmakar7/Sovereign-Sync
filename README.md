# 🛡️ Sovereign-Sync: DPDP-Compliant Privacy Gateway

**Sovereign-Sync** is an open-source, high-performance local proxy designed to redact Personally Identifiable Information (PII) in real-time before it reaches cloud LLMs. It ensures that businesses remain compliant with India's **Digital Personal Data Protection (DPDP) Act 2023** without sacrificing the power of GenAI.

---

## 🚀 The Problem
As organizations integrate AI APIs (like OpenAI, Claude, or Gemini), they inadvertently leak sensitive citizen data—Aadhar numbers, PAN details, and financial records—to foreign servers. The DPDP Act 2023 mandates that data fiduciaries protect this information. Current solutions are either expensive proprietary software or slow, purely Python-based tools.

## ✨ Features
- **Hybrid Redaction Engine:** High-speed **C-based** regex filtering for deterministic data (Aadhar, PAN) + **Python NLP** for contextual PII (Names, Organizations).
- **Session Vault:** An in-memory mapping system that masks data on the way out and "rehydrates" it on the way back.
- **Local-First Architecture:** Your sensitive data never leaves your local environment; only the anonymized prompt is sent to the AI.
- **Compliance Dashboard:** A web-based interface (with **Bengali** localization) providing real-time protection stats and DPDP audit logs.

## 🛠️ Technical Architecture
Sovereign-Sync uses a two-tier approach to balance speed and intelligence:
1.  **Tier 1 (The Shield):** A low-level module written in **C** using the `PCRE2` library. This handles the heavy lifting of scanning large blocks of text for patterns like Aadhar numbers with sub-millisecond latency.
2.  **Tier 2 (The Brain):** A **Python (FastAPI)** layer that uses Named Entity Recognition (NER) to catch complex PII and manages the communication with AI APIs.

## 📦 Installation (Development)
```bash
# 1. Clone the repository
git clone [https://github.com/your-username/sovereign-sync.git](https://github.com/your-username/sovereign-sync.git)
cd sovereign-sync

# 2. Compile the High-Speed C Module
gcc -shared -o core/pii_filter.so -fPIC core/pii_filter.c -lpcre2-8

# 3. Install Python dependencies
pip install -r requirements.txt

# 4. Start the Gateway
python main.py

