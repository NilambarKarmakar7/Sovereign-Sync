/*
 * Sovereign-Sync: C-Python Bridge Header
 * Copyright (c) 2026 - Licensed under GNU GPL v3.0
 */

#ifndef PII_FILTER_H
#define PII_FILTER_H

#include <stdlib.h>

/* PII Detection Result Structure */
typedef struct {
    char *text;           /* Detected PII text */
    int start_pos;        /* Start position in original text */
    int end_pos;          /* End position in original text */
    int pii_type;         /* Type of PII detected */
} pii_match_t;

/* PII Types */
#define PII_TYPE_AADHAR 1
#define PII_TYPE_PAN 2
#define PII_TYPE_PHONE 3
#define PII_TYPE_BANK_ACCOUNT 4
#define PII_TYPE_IFSC 5
#define PII_TYPE_EMAIL 6

/* Function declarations */
int pii_scanner_init(void);
void pii_scanner_cleanup(void);
pii_match_t* pii_scanner_detect(const char *text, int *num_matches);
void pii_scanner_free_matches(pii_match_t *matches, int num_matches);
const char* pii_type_name(int pii_type);

#endif /* PII_FILTER_H */