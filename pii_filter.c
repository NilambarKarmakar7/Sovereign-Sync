/*
 * Sovereign-Sync: C-Python Bridge for PII Detection
 * Copyright (c) 2026 - Licensed under GNU GPL v3.0
 * High-performance PII detection with Python tokenization integration
 * Thread-safe implementation for concurrent requests
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "pii_filter.h"

/* Simple pattern matching functions (no external regex dependency) */

/* Check if string is all digits */
static int is_all_digits(const char *str, int len) {
    for (int i = 0; i < len; i++) {
        if (!isdigit(str[i])) return 0;
    }
    return 1;
}

/* Check if string is all uppercase letters */
static int is_all_upper(const char *str, int len) {
    for (int i = 0; i < len; i++) {
        if (!isupper(str[i])) return 0;
    }
    return 1;
}

/* Check if string is alphanumeric with specific pattern */
static int is_alphanumeric_pattern(const char *str, int len) {
    if (len != 10) return 0;
    // PAN format: AAAAA9999A
    for (int i = 0; i < 5; i++) {
        if (!isupper(str[i])) return 0;
    }
    for (int i = 5; i < 9; i++) {
        if (!isdigit(str[i])) return 0;
    }
    if (!isupper(str[9])) return 0;
    return 1;
}

/* Check Aadhar pattern: 12 digits with optional spaces/dashes */
static int is_aadhar_pattern(const char *str, int len) {
    if (len < 12 || len > 14) return 0; // 12 digits + up to 2 separators

    int digit_count = 0;
    for (int i = 0; i < len; i++) {
        if (isdigit(str[i])) {
            digit_count++;
        } else if (str[i] != ' ' && str[i] != '-') {
            return 0;
        }
    }
    return digit_count == 12;
}

/* Check phone pattern: Indian mobile numbers */
static int is_phone_pattern(const char *str, int len) {
    if (len < 10 || len > 13) return 0;

    // Remove +91 or 91 prefix if present
    int start = 0;
    if (len >= 12 && str[0] == '+' && str[1] == '9' && str[2] == '1') {
        start = 3;
    } else if (len >= 11 && str[0] == '9' && str[1] == '1') {
        start = 2;
    }

    // Check if remaining is 10 digits starting with 6-9
    int remaining_len = len - start;
    if (remaining_len != 10) return 0;

    if (str[start] < '6' || str[start] > '9') return 0;

    for (int i = start + 1; i < len; i++) {
        if (!isdigit(str[i])) return 0;
    }
    return 1;
}

/* Check IFSC pattern: AAAA0AAAAA */
static int is_ifsc_pattern(const char *str, int len) {
    if (len != 11) return 0;

    for (int i = 0; i < 4; i++) {
        if (!isupper(str[i])) return 0;
    }
    if (str[4] != '0') return 0;
    for (int i = 5; i < 11; i++) {
        if (!isalnum(str[i])) return 0;
    }
    return 1;
}

/* Check email pattern (basic) */
static int is_email_pattern(const char *str, int len) {
    if (len < 5) return 0;

    const char *at = strchr(str, '@');
    if (!at) return 0;

    const char *dot = strchr(at + 1, '.');
    if (!dot || dot == at + 1) return 0;

    return 1;
}

/* Detect PII in text and return matches - Thread-safe, no global state */
pii_match_t* pii_scanner_detect(const char *text, int *num_matches) {
    if (!text) {
        *num_matches = 0;
        return NULL;
    }

    int text_len = strlen(text);
    pii_match_t *matches = NULL;
    *num_matches = 0;

    // Scan through text for PII patterns
    for (int i = 0; i < text_len; ) {
        int found = 0;
        int match_len = 0;
        int pii_type = 0;

        // Try different pattern checks
        for (int len = 1; len <= 20 && i + len <= text_len; len++) {
            if (is_aadhar_pattern(text + i, len)) {
                found = 1;
                match_len = len;
                pii_type = PII_TYPE_AADHAR;
                break;
            } else if (is_alphanumeric_pattern(text + i, len)) {
                found = 1;
                match_len = len;
                pii_type = PII_TYPE_PAN;
                break;
            } else if (is_phone_pattern(text + i, len)) {
                found = 1;
                match_len = len;
                pii_type = PII_TYPE_PHONE;
                break;
            } else if (len >= 9 && len <= 18 && is_all_digits(text + i, len)) {
                // Bank account (generic long number)
                found = 1;
                match_len = len;
                pii_type = PII_TYPE_BANK_ACCOUNT;
                break;
            } else if (is_ifsc_pattern(text + i, len)) {
                found = 1;
                match_len = len;
                pii_type = PII_TYPE_IFSC;
                break;
            } else if (is_email_pattern(text + i, len)) {
                found = 1;
                match_len = len;
                pii_type = PII_TYPE_EMAIL;
                break;
            }
        }

        if (found) {
            // Add match to results
            matches = realloc(matches, (*num_matches + 1) * sizeof(pii_match_t));
            if (!matches) {
                *num_matches = 0;
                return NULL;
            }

            matches[*num_matches].text = malloc(match_len + 1);
            if (!matches[*num_matches].text) {
                // Free previously allocated matches on failure
                for (int j = 0; j < *num_matches; j++) {
                    free(matches[j].text);
                }
                free(matches);
                *num_matches = 0;
                return NULL;
            }
            strncpy(matches[*num_matches].text, text + i, match_len);
            matches[*num_matches].text[match_len] = '\0';
            matches[*num_matches].start_pos = i;
            matches[*num_matches].end_pos = i + match_len;
            matches[*num_matches].pii_type = pii_type;

            (*num_matches)++;
            i += match_len;
        } else {
            i++;
        }
    }

    return matches;
}

/* Free matches array */
void pii_scanner_free_matches(pii_match_t *matches, int num_matches) {
    if (matches) {
        for (int i = 0; i < num_matches; i++) {
            free(matches[i].text);
        }
        free(matches);
    }
}

/* Get PII type name */
const char* pii_type_name(int pii_type) {
    switch (pii_type) {
        case PII_TYPE_AADHAR: return "AADHAR";
        case PII_TYPE_PAN: return "PAN";
        case PII_TYPE_PHONE: return "PHONE";
        case PII_TYPE_BANK_ACCOUNT: return "BANK_ACCOUNT";
        case PII_TYPE_IFSC: return "IFSC";
        case PII_TYPE_EMAIL: return "EMAIL";
        default: return "UNKNOWN";
    }
}

/* Initialize scanner - No-op for thread safety */
int pii_scanner_init(void) {
    return 1;
}

/* Cleanup scanner - No-op for thread safety */
void pii_scanner_cleanup(void) {
    /* No global state to clean up */
}