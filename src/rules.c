#include "rules.h"
#include <stdio.h>
#include <stdlib.h>

const char *severity_name(severity_t s)
{
    switch (s) {
        case SEV_CRITICAL: return "CRITICAL";
        case SEV_HIGH:     return "HIGH";
        case SEV_MEDIUM:   return "MEDIUM";
        default:           return "LOW";
    }
}

/* Built-in signatures. Patterns are POSIX ERE (compiled with REG_EXTENDED |
 * REG_ICASE on the generic rule only -- token formats are case-sensitive).
 * The order is broad-to-specific only for readability; every rule is tried.
 *
 * The final "Generic Secret Assignment" rule is entropy-gated: it captures the
 * value assigned to a sensitive-looking name and is only reported when that
 * value's observed Shannon entropy clears min_entropy, which is what keeps it
 * from flagging `password = changeme` while still catching random blobs. */
static rule_t rules[] = {
    { "AWS Access Key ID",
      "(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
      SEV_HIGH, 0, 0.0, {0} },

    { "AWS Secret Access Key",
      "aws_secret_access_key[\"' ]*[:=][\"' ]*([A-Za-z0-9/+]{40})",
      SEV_CRITICAL, 1, 0.0, {0} },

    { "GCP API Key",
      "AIza[0-9A-Za-z_-]{35}",
      SEV_HIGH, 0, 0.0, {0} },

    { "Google OAuth Access Token",
      "ya29\\.[0-9A-Za-z_-]{20,}",
      SEV_HIGH, 0, 0.0, {0} },

    { "GitHub Token",
      "gh[pousr]_[0-9A-Za-z]{36,}",
      SEV_HIGH, 0, 0.0, {0} },

    { "Slack Token",
      "xox[baprs]-[0-9A-Za-z-]{10,}",
      SEV_HIGH, 0, 0.0, {0} },

    { "Stripe Secret Key",
      "sk_(live|test)_[0-9A-Za-z]{16,}",
      SEV_CRITICAL, 0, 0.0, {0} },

    { "Twilio API Key",
      "SK[0-9a-fA-F]{32}",
      SEV_HIGH, 0, 0.0, {0} },

    { "SendGrid API Key",
      "SG\\.[0-9A-Za-z_-]{22}\\.[0-9A-Za-z_-]{43}",
      SEV_HIGH, 0, 0.0, {0} },

    { "JSON Web Token (JWT)",
      "eyJ[0-9A-Za-z_-]+\\.eyJ[0-9A-Za-z_-]+\\.[0-9A-Za-z_-]+",
      SEV_MEDIUM, 0, 0.0, {0} },

    { "Private Key (PEM)",
      "-----BEGIN ([A-Z ]+ )?PRIVATE KEY-----",
      SEV_CRITICAL, 0, 0.0, {0} },

    { "Generic Secret Assignment",
      "(api[_-]?key|secret|token|password|passwd|access[_-]?key|auth)"
      "[\"' ]*[:=][\"' ]*([^\"' \t]{12,})",
      SEV_MEDIUM, 2, 3.5, {0} },
};

#define N_RULES (sizeof(rules) / sizeof(rules[0]))

static int compiled = 0;

const rule_t *rules_init(size_t *count)
{
    if (!compiled) {
        for (size_t i = 0; i < N_RULES; i++) {
            int flags = REG_EXTENDED;
            /* Only the generic assignment rule is case-insensitive; vendor
             * token prefixes (AKIA, ghp_, AIza...) are case-sensitive. */
            if (rules[i].value_group == 2)
                flags |= REG_ICASE;
            int rc = regcomp(&rules[i].re, rules[i].pattern, flags);
            if (rc != 0) {
                char err[256];
                regerror(rc, &rules[i].re, err, sizeof(err));
                fprintf(stderr, "mole: failed to compile rule '%s': %s\n",
                        rules[i].name, err);
                /* Roll back what we compiled so far. */
                for (size_t j = 0; j < i; j++)
                    regfree(&rules[j].re);
                return NULL;
            }
        }
        compiled = 1;
    }
    if (count) *count = N_RULES;
    return rules;
}

void rules_free(void)
{
    if (!compiled) return;
    for (size_t i = 0; i < N_RULES; i++)
        regfree(&rules[i].re);
    compiled = 0;
}
