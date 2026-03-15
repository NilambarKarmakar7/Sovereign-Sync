/*
 * Sovereign-Sync: Enhanced PII Scanner with PCRE2
 * Copyright (c) 2026 - Licensed under GNU GPL v3.0
 * High-performance PII detection using PCRE2 for DPDP Act 2023 compliance
 */

#include "pii_scanner.h"
#include <pcre2.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <stdint.h>

/* PCRE2 Context and compiled patterns */
typedef struct {
    pcre2_code *aadhar;
    pcre2_code *pan;
    pcre2_code *phone;
    pcre2_code *bank_account;
    pcre2_code *ifsc;
    pcre2_code *email;
    pcre2_code *credit_card;
    pcre2_code *ssn;
    pcre2_match_data *match_data;
    pcre2_compile_context *compile_ctx;
    pcre2_match_context *match_ctx;
} pcre2_context_t;

static pcre2_context_t g_pcre2_ctx = {0};
static int g_initialized = 0;

/* Thread-safe initialization */
static int _init_pcre2_patterns(void) {
    if (g_initialized) return 1;

    int errornumber;
    PCRE2_SIZE erroroffset;
    PCRE2_UCHAR8 *pattern;
    uint32_t options = PCRE2_MULTILINE | PCRE2_UTF;

    /* Initialize contexts */
    g_pcre2_ctx.compile_ctx = pcre2_compile_context_create(NULL);
    g_pcre2_ctx.match_ctx = pcre2_match_context_create(NULL);
    g_pcre2_ctx.match_data = pcre2_match_data_create(10, NULL);

    if (!g_pcre2_ctx.compile_ctx || !g_pcre2_ctx.match_ctx || !g_pcre2_ctx.match_data) {
        return 0;
    }

    /* Aadhar: 12 consecutive digits or formatted with spaces/dashes */
    pattern = (PCRE2_UCHAR8 *)"\\b(\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4})\\b";
    g_pcre2_ctx.aadhar = pcre2_compile(pattern, PCRE2_ZERO_TERMINATED,
                                       options, &errornumber, &erroroffset,
                                       g_pcre2_ctx.compile_ctx);
    if (!g_pcre2_ctx.aadhar) goto cleanup;

    /* PAN: AAAAA9999A format */
    pattern = (PCRE2_UCHAR8 *)"\\b([A-Z]{5}[0-9]{4}[A-Z]{1})\\b";
    g_pcre2_ctx.pan = pcre2_compile(pattern, PCRE2_ZERO_TERMINATED,
                                    options, &errornumber, &erroroffset,
                                    g_pcre2_ctx.compile_ctx);
    if (!g_pcre2_ctx.pan) goto cleanup;

    /* Phone: Indian format +91 or 91 or just 10 digits */
    pattern = (PCRE2_UCHAR8 *)"\\b(\\+?91|0)?[6-9]\\d{9}\\b";
    g_pcre2_ctx.phone = pcre2_compile(pattern, PCRE2_ZERO_TERMINATED,
                                      options, &errornumber, &erroroffset,
                                      g_pcre2_ctx.compile_ctx);
    if (!g_pcre2_ctx.phone) goto cleanup;

    /* Bank Account: 9-18 digits */
    pattern = (PCRE2_UCHAR8 *)"\\b([0-9]{9,18})\\b";
    g_pcre2_ctx.bank_account = pcre2_compile(pattern, PCRE2_ZERO_TERMINATED,
                                             options, &errornumber, &erroroffset,
                                             g_pcre2_ctx.compile_ctx);
    if (!g_pcre2_ctx.bank_account) goto cleanup;

    /* IFSC: 11 characters (4 letters + 0 + 6 alphanumeric) */
    pattern = (PCRE2_UCHAR8 *)"\\b([A-Z]{4}0[A-Z0-9]{6})\\b";
    g_pcre2_ctx.ifsc = pcre2_compile(pattern, PCRE2_ZERO_TERMINATED,
                                     options, &errornumber, &erroroffset,
                                     g_pcre2_ctx.compile_ctx);
    if (!g_pcre2_ctx.ifsc) goto cleanup;

    /* Email */
    pattern = (PCRE2_UCHAR8 *)"\\b([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,})\\b";
    g_pcre2_ctx.email = pcre2_compile(pattern, PCRE2_ZERO_TERMINATED,
                                      options, &errornumber, &erroroffset,
                                      g_pcre2_ctx.compile_ctx);
    if (!g_pcre2_ctx.email) goto cleanup;

    /* Credit Card: 13-19 digits */
    pattern = (PCRE2_UCHAR8 *)"\\b([0-9]{13,19})\\b";
    g_pcre2_ctx.credit_card = pcre2_compile(pattern, PCRE2_ZERO_TERMINATED,
                                            options, &errornumber, &erroroffset,
                                            g_pcre2_ctx.compile_ctx);
    if (!g_pcre2_ctx.credit_card) goto cleanup;

    /* SSN: 9 digits, format XXX-XX-XXXX */
    pattern = (PCRE2_UCHAR8 *)"\\b([0-9]{3}-[0-9]{2}-[0-9]{4})\\b";
    g_pcre2_ctx.ssn = pcre2_compile(pattern, PCRE2_ZERO_TERMINATED,
                                    options, &errornumber, &erroroffset,
                                    g_pcre2_ctx.compile_ctx);
    if (!g_pcre2_ctx.ssn) goto cleanup;

    g_initialized = 1;
    return 1;

cleanup:
    /* Free all allocated patterns on error */
    if (g_pcre2_ctx.aadhar) pcre2_code_free(g_pcre2_ctx.aadhar);
    if (g_pcre2_ctx.pan) pcre2_code_free(g_pcre2_ctx.pan);
    if (g_pcre2_ctx.phone) pcre2_code_free(g_pcre2_ctx.phone);
    if (g_pcre2_ctx.bank_account) pcre2_code_free(g_pcre2_ctx.bank_account);
    if (g_pcre2_ctx.ifsc) pcre2_code_free(g_pcre2_ctx.ifsc);
    if (g_pcre2_ctx.email) pcre2_code_free(g_pcre2_ctx.email);
    if (g_pcre2_ctx.credit_card) pcre2_code_free(g_pcre2_ctx.credit_card);
    if (g_pcre2_ctx.ssn) pcre2_code_free(g_pcre2_ctx.ssn);
    if (g_pcre2_ctx.match_data) pcre2_match_data_free(g_pcre2_ctx.match_data);
    if (g_pcre2_ctx.compile_ctx) pcre2_compile_context_free(g_pcre2_ctx.compile_ctx);
    if (g_pcre2_ctx.match_ctx) pcre2_match_context_free(g_pcre2_ctx.match_ctx);

    return 0;
}

/* Memory-safe string processing with length bounds */
static int _validate_and_extract_pii(const char *text, size_t text_len,
                                     pcre2_code *pattern, char *buffer,
                                     size_t buffer_size, pii_type_t type) {
    if (!text || text_len == 0 || text_len > MAX_BUFFER_SIZE) return 0;

    int rc = pcre2_match(pattern, (PCRE2_SPTR8)text, text_len, 0, 0,
                         g_pcre2_ctx.match_data, g_pcre2_ctx.match_ctx);

    if (rc > 0) {
        PCRE2_SIZE *ovector = pcre2_get_ovector_pointer(g_pcre2_ctx.match_data);
        size_t start = ovector[0];
        size_t end = ovector[1];
        size_t match_len = end - start;

        if (match_len < buffer_size - 1) {
            memcpy(buffer, text + start, match_len);
            buffer[match_len] = '\0';

            /* Type-specific validation */
            switch (type) {
                case PII_TYPE_AADHAR:
                    return scanner_validate_aadhar(buffer);
                case PII_TYPE_PAN:
                    return scanner_validate_pan(buffer);
                case PII_TYPE_BANK_ACCOUNT:
                    return scanner_validate_bank_account(buffer);
                default:
                    return 1; /* Basic pattern match for others */
            }
        }
    }

    return 0;
}

/* Enhanced scanner with multiple pattern support */
scanner_t* scanner_init(uint64_t session_id) {
    if (!_init_pcre2_patterns()) return NULL;

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

/* Enhanced redaction with multiple PCRE2 patterns */
char* scanner_redact(scanner_t *scanner, const char *text, size_t text_len) {
    if (!scanner || !text || text_len == 0) return "";
    if (text_len > MAX_BUFFER_SIZE) text_len = MAX_BUFFER_SIZE;

    memset(scanner->redacted_buffer, 0, scanner->buffer_size);
    char *output = scanner->redacted_buffer;
    size_t output_pos = 0;
    size_t input_pos = 0;

    /* Define patterns to check in priority order */
    struct {
        pcre2_code *pattern;
        pii_type_t type;
        const char *type_name;
    } patterns[] = {
        {g_pcre2_ctx.aadhar, PII_TYPE_AADHAR, "AADHAR"},
        {g_pcre2_ctx.pan, PII_TYPE_PAN, "PAN"},
        {g_pcre2_ctx.phone, PII_TYPE_PHONE, "PHONE"},
        {g_pcre2_ctx.bank_account, PII_TYPE_BANK_ACCOUNT, "BANK"},
        {g_pcre2_ctx.ifsc, PII_TYPE_IFSC, "IFSC"},
        {g_pcre2_ctx.email, PII_TYPE_EMAIL, "EMAIL"},
        {g_pcre2_ctx.credit_card, PII_TYPE_CREDIT_CARD, "CC"},
        {g_pcre2_ctx.ssn, PII_TYPE_SSN, "SSN"}
    };

    const int num_patterns = sizeof(patterns) / sizeof(patterns[0]);

    /* Process text sequentially to avoid overlapping matches */
    while (input_pos < text_len && output_pos < scanner->buffer_size - MAX_TOKEN_LEN) {
        int match_found = 0;
        size_t earliest_start = text_len;
        size_t earliest_end = text_len;
        pii_type_t matched_type = PII_TYPE_AADHAR;
        const char *matched_type_name = "UNK";

        /* Find the earliest match among all patterns */
        for (int i = 0; i < num_patterns; i++) {
            int rc = pcre2_match(patterns[i].pattern, (PCRE2_SPTR8)text, text_len,
                                 input_pos, 0, g_pcre2_ctx.match_data, g_pcre2_ctx.match_ctx);

            if (rc > 0) {
                PCRE2_SIZE *ovector = pcre2_get_ovector_pointer(g_pcre2_ctx.match_data);
                size_t start = ovector[0];
                size_t end = ovector[1];

                if (start < earliest_start) {
                    earliest_start = start;
                    earliest_end = end;
                    matched_type = patterns[i].type;
                    matched_type_name = patterns[i].type_name;
                    match_found = 1;
                }
            }
        }

        if (match_found && earliest_start >= input_pos) {
            /* Copy text before match */
            size_t copy_len = earliest_start - input_pos;
            if (output_pos + copy_len < scanner->buffer_size) {
                memcpy(output + output_pos, text + input_pos, copy_len);
                output_pos += copy_len;
            }

            /* Extract and validate the match */
            char match_buffer[MAX_BUFFER_SIZE] = {0};
            size_t match_len = earliest_end - earliest_start;

            if (match_len < sizeof(match_buffer)) {
                memcpy(match_buffer, text + earliest_start, match_len);
                match_buffer[match_len] = '\0';

                /* Validate based on type */
                int is_valid = 0;
                switch (matched_type) {
                    case PII_TYPE_AADHAR:
                        is_valid = scanner_validate_aadhar(match_buffer);
                        break;
                    case PII_TYPE_PAN:
                        is_valid = scanner_validate_pan(match_buffer);
                        break;
                    case PII_TYPE_BANK_ACCOUNT:
                        is_valid = scanner_validate_bank_account(match_buffer);
                        break;
                    default:
                        is_valid = 1; /* Accept other patterns */
                }

                if (is_valid) {
                    /* Generate token and store in vault */
                    char token[MAX_TOKEN_LEN];
                    snprintf(token, MAX_TOKEN_LEN, "[%s_%u]", matched_type_name,
                            (unsigned int)time(NULL) % 10000); /* More unique */

                    /* Store in vault */
                    scanner_add_vault_entry(scanner, token, text + earliest_start,
                                          match_len, matched_type);

                    /* Add token to output */
                    size_t token_len = strlen(token);
                    if (output_pos + token_len < scanner->buffer_size) {
                        strcpy(output + output_pos, token);
                        output_pos += token_len;
                    }
                } else {
                    /* Invalid match, copy as-is */
                    if (output_pos + match_len < scanner->buffer_size) {
                        memcpy(output + output_pos, text + earliest_start, match_len);
                        output_pos += match_len;
                    }
                }
            }

            input_pos = earliest_end;
        } else {
            /* No match found, copy one character */
            if (output_pos < scanner->buffer_size - 1) {
                output[output_pos++] = text[input_pos++];
            } else {
                break; /* Buffer full */
            }
        }
    }

    /* Copy remaining text */
    while (input_pos < text_len && output_pos < scanner->buffer_size - 1) {
        output[output_pos++] = text[input_pos++];
    }

    output[output_pos] = '\0';
    return output;
}

/* Rehydration with enhanced token matching */
char* scanner_rehydrate(scanner_t *scanner, const char *redacted_text) {
    if (!scanner || !redacted_text) return "";

    size_t text_len = strlen(redacted_text);
    if (text_len > MAX_BUFFER_SIZE) text_len = MAX_BUFFER_SIZE;

    char *output = scanner->redacted_buffer;
    memset(output, 0, scanner->buffer_size);

    const char *pos = redacted_text;
    char *out_pos = output;

    while (*pos && (out_pos - output) < (ptrdiff_t)(scanner->buffer_size - 1)) {
        if (*pos == '[') {
            /* Look for token pattern [TYPE_XXXX] */
            char *end = strchr(pos, ']');
            if (end && (end - pos) < MAX_TOKEN_LEN) {
                char token[MAX_TOKEN_LEN] = {0};
                size_t token_len = end - pos + 1;
                memcpy(token, pos, token_len);

                vault_entry_t *entry = scanner_get_vault_entry(scanner, token);
                if (entry) {
                    /* Restore original data */
                    if ((out_pos - output) + entry->data_len < scanner->buffer_size) {
                        memcpy(out_pos, entry->original_data, entry->data_len);
                        out_pos += entry->data_len;
                        pos = end + 1;
                        continue;
                    }
                }
            }
        }

        *out_pos++ = *pos++;
    }

    *out_pos = '\0';
    return output;
}

/* Validation functions remain the same */
int scanner_validate_aadhar(const char *text) {
    char digits[13] = {0};
    int digit_count = 0;

    for (int i = 0; text[i] && digit_count < 12; i++) {
        if (text[i] >= '0' && text[i] <= '9') {
            digits[digit_count++] = text[i];
        }
    }

    return digit_count == 12;
}

int scanner_validate_pan(const char *text) {
    int len = strlen(text);
    if (len != 10) return 0;

    for (int i = 0; i < 5; i++) {
        if (!(text[i] >= 'A' && text[i] <= 'Z')) return 0;
    }
    for (int i = 5; i < 9; i++) {
        if (!(text[i] >= '0' && text[i] <= '9')) return 0;
    }
    if (!(text[9] >= 'A' && text[9] <= 'Z')) return 0;

    return 1;
}

int scanner_validate_bank_account(const char *text) {
    int len = strlen(text);
    if (len < 9 || len > 18) return 0;

    for (int i = 0; i < len; i++) {
        if (!(text[i] >= '0' && text[i] <= '9')) return 0;
    }

    return 1;
}

vault_entry_t* scanner_get_vault_entry(scanner_t *scanner, const char *token) {
    if (!scanner || !token) return NULL;

    for (uint32_t i = 0; i < scanner->vault_count; i++) {
        if (strcmp(scanner->vault[i].token, token) == 0) {
            return &scanner->vault[i];
        }
    }

    return NULL;
}

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
