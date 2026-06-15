#ifndef MOLE_SCAN_H
#define MOLE_SCAN_H

#include "rules.h"
#include "walk.h"
#include <stddef.h>

/* Triage states a finding can be moved through in the UI / CLI. */
typedef enum {
    TRIAGE_NEW = 0,    /* not yet reviewed            */
    TRIAGE_LEAK,       /* confirmed real leak         */
    TRIAGE_FALSE,      /* false positive              */
    TRIAGE_IGNORED     /* acknowledged, set aside     */
} triage_t;

const char *triage_name(triage_t t);

typedef struct finding {
    char       path[MOLE_MAX_PATH];
    long       line;                /* 1-based line number          */
    char       rule[64];            /* rule name                    */
    severity_t severity;
    double     entropy;             /* Shannon bits/char of secret  */
    char       redacted[128];       /* secret with middle masked    */
    char       preview[256];        /* the line, trimmed/truncated  */
    triage_t   triage;
    struct finding *next;
} finding_t;

typedef struct {
    finding_t *head;
    finding_t *tail;
    size_t     count;
    size_t     files_scanned;
    size_t     files_skipped;       /* binary / unreadable          */
    size_t     errors;              /* walk-level errors            */
} findings_t;

typedef struct {
    double min_entropy_generic;  /* override generic-rule gate (<=0 keeps rule default) */
    int    entropy_scan;         /* also flag standalone high-entropy blobs */
    double entropy_threshold;    /* bits/char for the standalone entropy scan */
    walk_opts walk;
} scan_opts;

scan_opts scan_default_opts(void);

/* Optional progress callback, invoked as files are scanned. */
typedef void (*scan_progress_cb)(size_t done, size_t total, void *ctx);

/* Recursively scan `root`, returning an allocated findings list (free with
 * findings_free). `progress` / `pctx` may be NULL. Returns NULL only on
 * allocation/setup failure. */
findings_t *scan_run(const char *root, const scan_opts *opts,
                     scan_progress_cb progress, void *pctx);

void findings_free(findings_t *f);

#endif /* MOLE_SCAN_H */
