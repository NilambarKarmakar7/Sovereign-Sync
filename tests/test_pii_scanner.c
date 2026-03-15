/*
 * Sovereign-Sync: PII Scanner Tests
 * Copyright (c) 2026 - Licensed under GNU GPL v3.0
 */

#include "pii_scanner.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int test_count = 0;
int test_passed = 0;

void assert_equal(int actual, int expected, const char *test_name) {
    test_count++;
    if (actual == expected) {
        test_passed++;
        printf("✓ %s\n", test_name);
    } else {
        printf("✗ %s (expected %d, got %d)\n", test_name, expected, actual);
    }
}

void test_aadhar_validation(void) {
    printf("\n=== Aadhar Validation Tests ===\n");
    
    assert_equal(scanner_validate_aadhar("1234 5678 9012"), 1, 
                 "Valid Aadhar with spaces");
    assert_equal(scanner_validate_aadhar("1234-5678-9012"), 1, 
                 "Valid Aadhar with dashes");
    assert_equal(scanner_validate_aadhar("123456789012"), 1, 
                 "Valid Aadhar without separators");
    assert_equal(scanner_validate_aadhar("123456789"), 0, 
                 "Invalid Aadhar (too short)");
    assert_equal(scanner_validate_aadhar("12345678901212"), 0, 
                 "Invalid Aadhar (too long)");
}

void test_pan_validation(void) {
    printf("\n=== PAN Validation Tests ===\n");
    
    assert_equal(scanner_validate_pan("AAAAA9999A"), 1, 
                 "Valid PAN format");
    assert_equal(scanner_validate_pan("ABCDE1234Z"), 1, 
                 "Valid PAN with different letters");
    assert_equal(scanner_validate_pan("AAAA99999"), 0, 
                 "Invalid PAN (9 chars instead of 10)");
    assert_equal(scanner_validate_pan("AAAAA999AA"), 0, 
                 "Invalid PAN (two letters at end)");
    assert_equal(scanner_validate_pan("aaaaa9999a"), 0, 
                 "Invalid PAN (lowercase)");
}

void test_bank_account_validation(void) {
    printf("\n=== Bank Account Validation Tests ===\n");
    
    assert_equal(scanner_validate_bank_account("123456789"), 1, 
                 "Valid bank account (9 digits)");
    assert_equal(scanner_validate_bank_account("12345678901234567"), 1, 
                 "Valid bank account (17 digits)");
    assert_equal(scanner_validate_bank_account("123456789012345678"), 1, 
                 "Valid bank account (18 digits)");
    assert_equal(scanner_validate_bank_account("12345678"), 0, 
                 "Invalid bank account (8 digits)");
    assert_equal(scanner_validate_bank_account("1234567890123456789"), 0, 
                 "Invalid bank account (19 digits)");
    assert_equal(scanner_validate_bank_account("1234567890a"), 0, 
                 "Invalid bank account (contains letter)");
}

void test_scanner_initialization(void) {
    printf("\n=== Scanner Initialization Tests ===\n");
    
    scanner_t *scanner = scanner_init(12345);
    
    if (scanner != NULL) {
        test_count++;
        test_passed++;
        printf("✓ Scanner initialization successful\n");
    } else {
        test_count++;
        printf("✗ Scanner initialization failed\n");
        return;
    }
    
    if (scanner->session_id == 12345) {
        test_count++;
        test_passed++;
        printf("✓ Session ID correctly set\n");
    } else {
        test_count++;
        printf("✗ Session ID not set correctly\n");
    }
    
    if (scanner->vault_count == 0) {
        test_count++;
        test_passed++;
        printf("✓ Vault initialized as empty\n");
    } else {
        test_count++;
        printf("✗ Vault not empty after init\n");
    }
    
    if (scanner->redacted_buffer != NULL) {
        test_count++;
        test_passed++;
        printf("✓ Redaction buffer allocated\n");
    } else {
        test_count++;
        printf("✗ Redaction buffer not allocated\n");
    }
    
    scanner_free(scanner);
}

void test_vault_operations(void) {
    printf("\n=== Vault Operations Tests ===\n");
    
    scanner_t *scanner = scanner_init(99999);
    
    if (!scanner) {
        printf("✗ Failed to initialize scanner for vault test\n");
        return;
    }
    
    /* Test adding vault entry */
    int result = scanner_add_vault_entry(scanner, "[TEST_1]", 
                                        "sensitive_data", 14, PII_TYPE_AADHAR);
    if (result) {
        test_count++;
        test_passed++;
        printf("✓ Vault entry added successfully\n");
    } else {
        test_count++;
        printf("✗ Failed to add vault entry\n");
    }
    
    /* Test vault retrieval */
    vault_entry_t *entry = scanner_get_vault_entry(scanner, "[TEST_1]");
    if (entry != NULL && strcmp(entry->token, "[TEST_1]") == 0) {
        test_count++;
        test_passed++;
        printf("✓ Vault entry retrieved successfully\n");
    } else {
        test_count++;
        printf("✗ Failed to retrieve vault entry\n");
    }
    
    /* Test non-existent retrieval */
    entry = scanner_get_vault_entry(scanner, "[NONEXIST]");
    if (entry == NULL) {
        test_count++;
        test_passed++;
        printf("✓ Non-existent entry returns NULL\n");
    } else {
        test_count++;
        printf("✗ Non-existent entry should return NULL\n");
    }
    
    scanner_free(scanner);
}

void test_redaction_basic(void) {
    printf("\n=== Basic Redaction Tests ===\n");
    
    scanner_t *scanner = scanner_init(11111);
    
    if (!scanner) {
        printf("✗ Failed to initialize scanner for redaction test\n");
        return;
    }
    
    /* Test simple text without PII */
    const char *text1 = "This is a simple message with no PII";
    char *result1 = scanner_redact(scanner, text1, strlen(text1));
    
    if (result1 != NULL && strcmp(result1, text1) == 0) {
        test_count++;
        test_passed++;
        printf("✓ Text without PII passes through unchanged\n");
    } else {
        test_count++;
        printf("✗ Text without PII was modified\n");
    }
    
    /* Test text with Aadhar */
    const char *text2 = "My Aadhar is 1234-5678-9012 and this is secret";
    char *result2 = scanner_redact(scanner, text2, strlen(text2));
    
    if (result2 != NULL && strstr(result2, "[AADHAR") != NULL) {
        test_count++;
        test_passed++;
        printf("✓ Aadhar detected and redacted with token\n");
    } else {
        test_count++;
        printf("✗ Aadhar not properly redacted\n");
    }
    
    if (strstr(result2, "1234-5678-9012") == NULL) {
        test_count++;
        test_passed++;
        printf("✓ Original Aadhar removed from output\n");
    } else {
        test_count++;
        printf("✗ Original Aadhar still present in output\n");
    }
    
    scanner_free(scanner);
}

int main(void) {
    printf("╔════════════════════════════════════════════════╗\n");
    printf("║  Sovereign-Sync: PII Scanner Test Suite       ║\n");
    printf("║  PCRE2-based Regex Pattern Validation         ║\n");
    printf("╚════════════════════════════════════════════════╝\n");
    
    test_aadhar_validation();
    test_pan_validation();
    test_bank_account_validation();
    test_scanner_initialization();
    test_vault_operations();
    test_redaction_basic();
    
    printf("\n╔════════════════════════════════════════════════╗\n");
    printf("  Test Results: %d / %d passed\n", test_passed, test_count);
    printf("╚════════════════════════════════════════════════╝\n");
    
    return (test_passed == test_count) ? 0 : 1;
}
