/*
 * Sovereign-Sync: PII Scanner Implementation
 * Copyright (c) 2026 - Licensed under GNU GPL v3.0
 * 
 * High-performance PII detection using PCRE2
 * Designed for sub-millisecond latency on API gateway
 */

#include "pii_scanner.h"
#include <pcre2.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

/* Compiled regex patterns (lazy-initialized) */
typedef struct {
    pcre2_code *aadhar;
    pcre2_code *pan;
    pcre2_code *bank_account;
    pcre2_code *ifsc;
    pcre2_code *email;
    pcre2_code *phone;
    pcre2_code *credit_card;
    pcre2_code *ssn;
} regex_cache_t;

static regex_cache_t g_regex_cache = {0};
static int g_cache_initialized = 0;

/* Atomic counter for unique token generation */
static uint32_t g_token_counter = 1000;

/**
 * Initialize PCRE2 regex patterns
 * Patterns optimized for Indian identity systems and international standards
 */
static int _init_regex_patterns(void) {
    if (g_cache_initialized) return 1;
    
    int errornumber;
    PCRE2_SIZE erroroffset;
    PCRE2_UCHAR8 *pattern;
    
    /* Aadhar: 12 consecutive digits or formatted with spaces/dashes */
    pattern = (PCRE2_UCHAR8 *)"\\b(\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4})\\b";
    g_regex_cache.aadhar = pcre2_compile(pattern, PCRE2_ZERO_TERMINATED,
                                         PCRE2_MULTILINE, &errornumber, &erroroffset, NULL);
    if (!g_regex_cache.aadhar) return 0;
    
    /* PAN: Format AAAAA9999A (5 letters, 4 digits, 1 letter) */
    pattern = (PCRE2_UCHAR8 *)"\\b([A-Z]{5}[0-9]{4}[A-Z]{1})\\b";
    g_regex_cache.pan = pcre2_compile(pattern, PCRE2_ZERO_TERMINATED,
                                      PCRE2_MULTILINE, &errornumber, &erroroffset, NULL);
    if (!g_regex_cache.pan) return 0;
    
    /* Bank Account: 9-18 digits */
    pattern = (PCRE2_UCHAR8 *)"\\b([0-9]{9,18})\\b";
    g_regex_cache.bank_account = pcre2_compile(pattern, PCRE2_ZERO_TERMINATED,
                                               PCRE2_MULTILINE, &errornumber, &erroroffset, NULL);
    if (!g_regex_cache.bank_account) return 0;
    
    /* IFSC Code: 11 characters (4 letters + 0 + 6 alphanumeric) */
    pattern = (PCRE2_UCHAR8 *)"\\b([A-Z]{4}0[A-Z0-9]{6})\\b";
    g_regex_cache.ifsc = pcre2_compile(pattern, PCRE2_ZERO_TERMINATED,
                                       PCRE2_MULTILINE, &errornumber, &erroroffset, NULL);
    if (!g_regex_cache.ifsc) return 0;
    
    /* Email */
    pattern = (PCRE2_UCHAR8 *)"\\b([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,})\\b";
    g_regex_cache.email = pcre2_compile(pattern, PCRE2_ZERO_TERMINATED,
                                        PCRE2_MULTILINE, &errornumber, &erroroffset, NULL);
    if (!g_regex_cache.email) return 0;
    
    /* Phone: Indian format +91 or 91 or just 10 digits */
    pattern = (PCRE2_UCHAR8 *)"\\b(\\+?91|0)?[6-9]\\d{9}\\b";
    g_regex_cache.phone = pcre2_compile(pattern, PCRE2_ZERO_TERMINATED,
                                        PCRE2_MULTILINE, &errornumber, &erroroffset, NULL);
    if (!g_regex_cache.phone) return 0;
    
    /* Credit Card: 13-19 digits (Luhn validated in wrapper) */
    pattern = (PCRE2_UCHAR8 *)"\\b([0-9]{13,19})\\b";
    g_regex_cache.credit_card = pcre2_compile(pattern, PCRE2_ZERO_TERMINATED,
                                              PCRE2_MULTILINE, &errornumber, &erroroffset, NULL);
    if (!g_regex_cache.credit_card) return 0;
    
    /* SSN (US): 9 digits, format XXX-XX-XXXX */
    pattern = (PCRE2_UCHAR8 *)"\\b([0-9]{3}-[0-9]{2}-[0-9]{4})\\b";
    g_regex_cache.ssn = pcre2_compile(pattern, PCRE2_ZERO_TERMINATED,
                                      PCRE2_MULTILINE, &errornumber, &erroroffset, NULL);
    if (!g_regex_cache.ssn) return 0;
    
    g_cache_initialized = 1;
    return 1;
}

/**
 * Generate unique token for PII entry
 */
static void _generate_token(pii_type_t type, char *buffer) {
    const char *type_name = "PII";
    
    switch (type) {
        case PII_TYPE_AADHAR:
            type_name = "AADHAR";
            break;
        case PII_TYPE_PAN:
            type_name = "PAN";
            break;
        case PII_TYPE_BANK_ACCOUNT:
            type_name = "BANK";
            break;
        case PII_TYPE_IFSC:
            type_name = "IFSC";
            break;
        case PII_TYPE_EMAIL:
            type_name = "EMAIL";
            break;
        case PII_TYPE_PHONE:
            type_name = "PHONE";
            break;
        case PII_TYPE_CREDIT_CARD:
            type_name = "CC";
            break;
        case PII_TYPE_SSN:
            type_name = "SSN";
            break;
        default:
            type_name = "UNK";
    }
    
    snprintf(buffer, MAX_TOKEN_LEN, "[%s_%u]", type_name, g_token_counter++);
}

/**
 * Validate Aadhar using Verhoeff algorithm
 */
int scanner_validate_aadhar(const char *text) {
    /* Extract 12 digits from text (handling spaces and dashes) */
    char digits[13] = {0};
    int digit_count = 0;
    
    for (int i = 0; text[i] && digit_count < 12; i++) {
        if (text[i] >= '0' && text[i] <= '9') {
            digits[digit_count++] = text[i];
        }
    }
    
    if (digit_count != 12) return 0;
    
    /* Basic Aadhar validation (simplified check for demo) */
    /* Real implementation should use Verhoeff algorithm */
    return digit_count == 12;
}

/**
 * Validate PAN number format
 */
int scanner_validate_pan(const char *text) {
    int len = strlen(text);
    if (len != 10) return 0;
    
    /* AAAAA9999A format */
    for (int i = 0; i < 5; i++) {
        if (!(text[i] >= 'A' && text[i] <= 'Z')) return 0;
    }
    for (int i = 5; i < 9; i++) {
        if (!(text[i] >= '0' && text[i] <= '9')) return 0;
    }
    if (!(text[9] >= 'A' && text[9] <= 'Z')) return 0;
    
    return 1;
}

/**
 * Validate bank account format
 */
int scanner_validate_bank_account(const char *text) {
    int len = strlen(text);
    /* Indian bank accounts are 9-18 digits */
    if (len < 9 || len > 18) return 0;
    
    for (int i = 0; i < len; i++) {
        if (!(text[i] >= '0' && text[i] <= '9')) return 0;
    }
    
    return 1;
}

/**
 * Create new scanner instance for a session
 */
scanner_t* scanner_init(uint64_t session_id) {
    if (!_init_regex_patterns()) return NULL;
    
    scanner_t *scanner = calloc(1, sizeof(scanner_t));
    if (!scanner) return NULL;
    
    scanner->session_id = session_id;
    scanner->buffer_size = MAX_BUFFER_SIZE;
    scanner->redacted_buffer = malloc(scanner->buffer_size);
    
    if (!scanner->redacted_buffer) {
        free(scanner);
        return NULL;
    }
    
    return scanner;
}

/**
 * Free scanner instance and securely wipe sensitive data
 */
void scanner_free(scanner_t *scanner) {
    if (!scanner) return;
    
    /* Securely wipe vault entries */
    for (uint32_t i = 0; i < scanner->vault_count; i++) {
        if (scanner->vault[i].original_data) {
            memset(scanner->vault[i].original_data, 0, scanner->vault[i].data_len);
            free(scanner->vault[i].original_data);
        }
        memset(&scanner->vault[i], 0, sizeof(vault_entry_t));
    }
    
    /* Wipe redaction buffer */
    if (scanner->redacted_buffer) {
        memset(scanner->redacted_buffer, 0, scanner->buffer_size);
        free(scanner->redacted_buffer);
    }
    
    free(scanner);
}

/**
 * Core redaction logic
 */
char* scanner_redact(scanner_t *scanner, const char *text, size_t text_len) {
    if (!scanner || !text || text_len == 0) return "";
    if (text_len > MAX_BUFFER_SIZE) text_len = MAX_BUFFER_SIZE;
    
    pcre2_match_data *match_data = pcre2_match_data_create(10, NULL);
    if (!match_data) return "";
    
    memset(scanner->redacted_buffer, 0, scanner->buffer_size);
    char *output = scanner->redacted_buffer;
    size_t output_pos = 0;
    size_t input_pos = 0;
    
    /* Try to match Aadhar */
    int rc = pcre2_match(g_regex_cache.aadhar, (PCRE2_SPTR8)text, text_len, 
                         0, 0, match_data, NULL);
    if (rc > 0) {
        PCRE2_SIZE *ovector = pcre2_get_ovector_pointer(match_data);
        size_t start = ovector[0];
        size_t end = ovector[1];
        
        /* Validate before redacting */
        char temp[50] = {0};
        strncpy(temp, text + start, end - start);
        if (scanner_validate_aadhar(temp)) {
            char token[MAX_TOKEN_LEN];
            _generate_token(PII_TYPE_AADHAR, token);
            
            /* Copy before match */
            strncpy(output + output_pos, text + input_pos, start - input_pos);
            output_pos += (start - input_pos);
            
            /* Store in vault and add token */
            scanner_add_vault_entry(scanner, token, text + start, end - start, PII_TYPE_AADHAR);
            strcpy(output + output_pos, token);
            output_pos += strlen(token);
            
            input_pos = end;
        }
    }
    
    /* Try to match PAN */
    rc = pcre2_match(g_regex_cache.pan, (PCRE2_SPTR8)text, text_len, 
                     0, 0, match_data, NULL);
    if (rc > 0) {
        PCRE2_SIZE *ovector = pcre2_get_ovector_pointer(match_data);
        size_t start = ovector[0];
        size_t end = ovector[1];
        
        char temp[20] = {0};
        strncpy(temp, text + start, end - start);
        if (scanner_validate_pan(temp)) {
            char token[MAX_TOKEN_LEN];
            _generate_token(PII_TYPE_PAN, token);
            
            strncpy(output + output_pos, text + input_pos, start - input_pos);
            output_pos += (start - input_pos);
            
            scanner_add_vault_entry(scanner, token, text + start, end - start, PII_TYPE_PAN);
            strcpy(output + output_pos, token);
            output_pos += strlen(token);
            
            input_pos = end;
        }
    }
    
    /* Try to match Bank Account */
    rc = pcre2_match(g_regex_cache.bank_account, (PCRE2_SPTR8)text, text_len, 
                     0, 0, match_data, NULL);
    if (rc > 0) {
        PCRE2_SIZE *ovector = pcre2_get_ovector_pointer(match_data);
        size_t start = ovector[0];
        size_t end = ovector[1];
        
        char temp[25] = {0};
        strncpy(temp, text + start, end - start);
        if (scanner_validate_bank_account(temp)) {
            char token[MAX_TOKEN_LEN];
            _generate_token(PII_TYPE_BANK_ACCOUNT, token);
            
            strncpy(output + output_pos, text + input_pos, start - input_pos);
            output_pos += (start - input_pos);
            
            scanner_add_vault_entry(scanner, token, text + start, end - start, PII_TYPE_BANK_ACCOUNT);
            strcpy(output + output_pos, token);
            output_pos += strlen(token);
            
            input_pos = end;
        }
    }
    
    /* Copy remaining text */
    if (input_pos < text_len) {
        strncpy(output + output_pos, text + input_pos, text_len - input_pos);
        output_pos += (text_len - input_pos);
    }
    
    output[output_pos] = '\0';
    
    pcre2_match_data_free(match_data);
    return output;
}

/**
 * Rehydrate redacted text with original PII from vault
 */
char* scanner_rehydrate(scanner_t *scanner, const char *redacted_text) {
    if (!scanner || !redacted_text) return "";
    
    size_t text_len = strlen(redacted_text);
    if (text_len > MAX_BUFFER_SIZE) text_len = MAX_BUFFER_SIZE;
    
    char *output = scanner->redacted_buffer;
    memset(output, 0, scanner->buffer_size);
    
    const char *pos = redacted_text;
    char *out_pos = output;
    
    while (*pos) {
        if (*pos == '[') {
            /* Found potential token */
            char *end = strchr(pos, ']');
            if (end) {
                char token[MAX_TOKEN_LEN] = {0};
                strncpy(token, pos, end - pos + 1);
                
                vault_entry_t *entry = scanner_get_vault_entry(scanner, token);
                if (entry) {
                    /* Copy original data */
                    strncpy(out_pos, entry->original_data, entry->data_len);
                    out_pos += entry->data_len;
                    pos = end + 1;
                    continue;
                }
            }
        }
        
        *out_pos++ = *pos++;
    }
    
    *out_pos = '\0';
    return output;
}

/**
 * Get vault entry by token
 */
vault_entry_t* scanner_get_vault_entry(scanner_t *scanner, const char *token) {
    if (!scanner || !token) return NULL;
    
    for (uint32_t i = 0; i < scanner->vault_count; i++) {
        if (strcmp(scanner->vault[i].token, token) == 0) {
            return &scanner->vault[i];
        }
    }
    
    return NULL;
}

/**
 * Add entry to vault
 */
int scanner_add_vault_entry(scanner_t *scanner, const char *token,
                            const char *original_data, size_t len, pii_type_t type) {
    if (!scanner || scanner->vault_count >= MAX_REDACTIONS) return 0;
    
    vault_entry_t *entry = &scanner->vault[scanner->vault_count];
    
    strncpy(entry->token, token, MAX_TOKEN_LEN - 1);
    entry->original_data = malloc(len);
    if (!entry->original_data) return 0;
    
    memcpy(entry->original_data, original_data, len);
    entry->data_len = len;
    entry->type = type;
    entry->timestamp = time(NULL);
    
    scanner->vault_count++;
    return 1;
}
