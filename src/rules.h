#ifndef MOLE_RULES_H
#define MOLE_RULES_H

#include <regex.h>
#include <stddef.h>

typedef enum {
    SEV_LOW = 0,
    SEV_MEDIUM,
    SEV_HIGH,
    SEV_CRITICAL
} severity_t;

const char *severity_name(severity_t s);

/* A signature: a POSIX extended regex plus metadata. `value_group` selects
 * which capture group holds the actual secret (0 = whole match); the scanner
 * redacts and entropy-scores that group. `min_entropy` (bits/char), when > 0,
 * suppresses the finding unless the captured value's Shannon entropy clears
 * it -- this is how the broad "generic assignment" rule avoids firing on
 * ordinary config values. */
typedef struct {
    const char *name;
    const char *pattern;
    severity_t  severity;
    int         value_group;
    double      min_entropy;
    regex_t     re;          /* compiled lazily by rules_init() */
} rule_t;

/* Compile every built-in rule. Returns the table and its length via *count.
 * Returns NULL on a compile failure (should not happen for the built-ins). */
const rule_t *rules_init(size_t *count);

/* Free compiled regexes acquired by rules_init(). */
void rules_free(void);

#endif /* MOLE_RULES_H */
