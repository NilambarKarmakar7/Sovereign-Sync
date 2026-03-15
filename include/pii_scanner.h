/*
 * Sovereign-Sync: PII Scanner Header
 * Copyright (c) 2026 - Licensed under GNU GPL v3.0
 * 
 * High-performance PII detection using PCRE2 for compliance with
 * India's Digital Personal Data Protection (DPDP) Act 2023
 */

#ifndef PII_SCANNER_H
#define PII_SCANNER_H

#include <stddef.h>
#include <stdint.h>

#define MAX_REDACTIONS 1000
#define MAX_TOKEN_LEN 32
#define MAX_BUFFER_SIZE 1024 * 1024  // 1MB max request size

/* PII Detection Types */
typedef enum {
    PII_TYPE_AADHAR = 1,
    PII_TYPE_PAN = 2,
    PII_TYPE_BANK_ACCOUNT = 4,
    PII_TYPE_IFSC = 8,
    PII_TYPE_EMAIL = 16,
    PII_TYPE_PHONE = 32,
    PII_TYPE_SSN = 64,
    PII_TYPE_CREDIT_CARD = 128
} pii_type_t;

/* Session Vault Entry - maps tokens to original data */
typedef struct {
    char token[MAX_TOKEN_LEN];
    char *original_data;
    size_t data_len;
    pii_type_t type;
    uint64_t timestamp;
} vault_entry_t;

/* Redaction Info */
typedef struct {
    size_t offset;
    size_t length;
    pii_type_t type;
    char token[MAX_TOKEN_LEN];
} redaction_t;

/* Main Scanner Context */
typedef struct {
    redaction_t redactions[MAX_REDACTIONS];
    vault_entry_t vault[MAX_REDACTIONS];
    uint32_t redaction_count;
    uint32_t vault_count;
    char *redacted_buffer;
    size_t buffer_size;
    uint64_t session_id;
} scanner_t;

/* Function Prototypes */
scanner_t* scanner_init(uint64_t session_id);
void scanner_free(scanner_t *scanner);

/**
 * Scan text for PII and redact sensitive data
 * @param scanner: Context for this session
 * @param text: Input text to scan
 * @param text_len: Length of input text
 * @return: Pointer to redacted text (caller must not free)
 */
char* scanner_redact(scanner_t *scanner, const char *text, size_t text_len);

/**
 * Restore original data from redacted text using vault
 * @param scanner: Context containing vault entries
 * @param redacted_text: Text with [PII_*] tokens
 * @return: Pointer to restored text (caller must not free)
 */
char* scanner_rehydrate(scanner_t *scanner, const char *redacted_text);

/**
 * Validate Aadhar number (12 digits)
 */
int scanner_validate_aadhar(const char *text);

/**
 * Validate PAN number (10-character format: 5 letters, 4 digits, 1 letter)
 */
int scanner_validate_pan(const char *text);

/**
 * Validate Bank Account (15-18 digits)
 */
int scanner_validate_bank_account(const char *text);

/**
 * Get vault entry by token
 */
vault_entry_t* scanner_get_vault_entry(scanner_t *scanner, const char *token);

/**
 * Record vault entry
 */
int scanner_add_vault_entry(scanner_t *scanner, const char *token, 
                            const char *original_data, size_t len, pii_type_t type);

#endif /* PII_SCANNER_H */
