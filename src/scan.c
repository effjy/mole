#include "scan.h"
#include "entropy.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>

scan_opts scan_default_opts(void)
{
    scan_opts o;
    o.min_entropy_generic = 0.0;   /* keep each rule's built-in gate */
    o.entropy_scan        = 1;
    o.entropy_threshold   = 4.3;   /* high for base64; near the random-blob floor */
    o.walk                = walk_default_opts();
    return o;
}

const char *triage_name(triage_t t)
{
    switch (t) {
        case TRIAGE_LEAK:    return "LEAK";
        case TRIAGE_FALSE:   return "FALSE+";
        case TRIAGE_IGNORED: return "IGNORED";
        default:             return "NEW";
    }
}

/* Mask the middle of a secret, keeping a short head/tail for recognisability:
 * "AKIAIOSFODNN7EXAMPLE" -> "AKIA************MPLE". */
static void redact(const char *s, size_t len, char *out, size_t outsz)
{
    if (len >= outsz) len = outsz - 1;
    size_t keep = 4;
    if (len <= 2 * keep) {
        /* Too short to keep both ends without revealing it; mask all but 1. */
        size_t shown = len > 4 ? 2 : 0;
        for (size_t i = 0; i < len && i < outsz - 1; i++)
            out[i] = (i < shown) ? s[i] : '*';
        out[len < outsz ? len : outsz - 1] = '\0';
        return;
    }
    size_t pos = 0;
    for (size_t i = 0; i < keep; i++)            out[pos++] = s[i];
    for (size_t i = keep; i < len - keep; i++)   out[pos++] = '*';
    for (size_t i = len - keep; i < len; i++)    out[pos++] = s[i];
    out[pos] = '\0';
}

/* Copy a line into preview, trimming leading whitespace and truncating. */
static void make_preview(const char *line, char *out, size_t outsz)
{
    while (*line == ' ' || *line == '\t') line++;
    size_t i = 0;
    for (; line[i] && line[i] != '\n' && i < outsz - 1; i++)
        out[i] = (line[i] == '\t') ? ' ' : line[i];
    out[i] = '\0';
}

static finding_t *finding_new(const char *rel, long lineno,
                              const char *rule, severity_t sev,
                              const char *secret, size_t seclen,
                              const char *line)
{
    finding_t *f = calloc(1, sizeof(*f));
    if (!f) return NULL;
    snprintf(f->path, sizeof(f->path), "%s", rel);
    f->line = lineno;
    snprintf(f->rule, sizeof(f->rule), "%s", rule);
    f->severity = sev;
    f->entropy  = shannon_entropy_bits(secret, seclen);
    redact(secret, seclen, f->redacted, sizeof(f->redacted));
    make_preview(line, f->preview, sizeof(f->preview));
    f->triage = TRIAGE_NEW;
    return f;
}

static void findings_append(findings_t *fs, finding_t *f)
{
    if (!f) return;
    if (!fs->head) fs->head = fs->tail = f;
    else { fs->tail->next = f; fs->tail = f; }
    fs->count++;
}

/* A base64/hex-ish token character, for the standalone entropy scan. */
static int is_token_char(int c)
{
    return isalnum(c) || c == '+' || c == '/' || c == '_' || c == '-' || c == '=';
}

/* Detect a binary file by scanning the first chunk for a NUL byte. */
static int looks_binary(const char *buf, size_t n)
{
    for (size_t i = 0; i < n; i++)
        if (buf[i] == '\0') return 1;
    return 0;
}

typedef struct {
    findings_t   *fs;
    const rule_t *rules;
    size_t        nrules;
    const scan_opts *opts;
} scan_ctx;

/* One detector hit on a line, before dedup. */
typedef struct {
    const char *name;
    severity_t  sev;
    size_t      start;   /* byte offset of the secret within the line */
    size_t      len;
} cand_t;

#define MAX_CANDS 64

/* True if a higher-severity candidate overlaps span [start,start+len).
 * This is what collapses the "specific rule + generic rule + entropy scan all
 * fired on one token" case down to the single most informative finding. */
static int superseded(const cand_t *cands, size_t n, size_t self,
                      size_t start, size_t len)
{
    size_t end = start + len;
    for (size_t i = 0; i < n; i++) {
        if (i == self) continue;
        size_t s2 = cands[i].start, e2 = s2 + cands[i].len;
        int overlap = (start < e2) && (s2 < end);
        if (!overlap) continue;
        if (cands[i].sev > cands[self].sev) return 1;
        /* Same severity, overlapping: keep the earlier (lower-index) one. */
        if (cands[i].sev == cands[self].sev && i < self) return 1;
    }
    return 0;
}

static void scan_line(scan_ctx *c, const char *rel, long lineno, const char *line)
{
    cand_t cands[MAX_CANDS];
    size_t nc = 0;

    /* --- signature rules --- */
    for (size_t i = 0; i < c->nrules && nc < MAX_CANDS; i++) {
        const rule_t *r = &c->rules[i];
        regmatch_t m[4];
        if (regexec(&r->re, line, 4, m, 0) != 0)
            continue;

        int g = r->value_group;
        if (g >= 4 || m[g].rm_so < 0) g = 0;     /* fall back to whole match */
        const char *secret = line + m[g].rm_so;
        size_t seclen = (size_t)(m[g].rm_eo - m[g].rm_so);

        double gate = r->min_entropy;
        if (r->min_entropy > 0.0 && c->opts->min_entropy_generic > 0.0)
            gate = c->opts->min_entropy_generic;
        if (gate > 0.0 && shannon_entropy_bits(secret, seclen) < gate)
            continue;

        cands[nc++] = (cand_t){ r->name, r->severity,
                                (size_t)m[g].rm_so, seclen };
    }

    /* --- standalone high-entropy blob scan --- */
    if (c->opts->entropy_scan) {
        const char *p = line;
        while (*p && nc < MAX_CANDS) {
            if (!is_token_char((unsigned char)*p)) { p++; continue; }
            const char *start = p;
            while (is_token_char((unsigned char)*p)) p++;
            size_t len = (size_t)(p - start);
            if (len >= 20 && len <= 100) {
                double e = shannon_entropy_bits(start, len);
                if (e >= c->opts->entropy_threshold)
                    cands[nc++] = (cand_t){ "High-Entropy String", SEV_LOW,
                                            (size_t)(start - line), len };
            }
        }
    }

    /* Emit only the surviving (non-superseded) candidates. */
    for (size_t i = 0; i < nc; i++) {
        if (superseded(cands, nc, i, cands[i].start, cands[i].len))
            continue;
        findings_append(c->fs,
            finding_new(rel, lineno, cands[i].name, cands[i].sev,
                        line + cands[i].start, cands[i].len, line));
    }
}

static int file_cb(const char *full, const char *rel, void *ctx)
{
    scan_ctx *c = ctx;

    FILE *fp = fopen(full, "rb");
    if (!fp) { c->fs->files_skipped++; return 0; }

    /* Peek for binary content. */
    char peek[4096];
    size_t pn = fread(peek, 1, sizeof(peek), fp);
    if (looks_binary(peek, pn)) {
        c->fs->files_skipped++;
        fclose(fp);
        return 0;
    }
    rewind(fp);

    c->fs->files_scanned++;

    char  *line = NULL;
    size_t cap  = 0;
    ssize_t n;
    long   lineno = 0;
    while ((n = getline(&line, &cap, fp)) != -1) {
        lineno++;
        if (n > 0 && line[n - 1] == '\n') line[n - 1] = '\0';
        scan_line(c, rel, lineno, line);
    }
    free(line);
    fclose(fp);
    return 0;
}

typedef struct {
    scan_progress_cb cb;
    void            *ctx;
    size_t           total;
    size_t           done;
    scan_ctx        *sc;
} progress_wrap;

/* We wrap file_cb to report progress without the walker knowing about it. */
static int file_cb_progress(const char *full, const char *rel, void *ctx)
{
    progress_wrap *w = ctx;
    int rc = file_cb(full, rel, w->sc);
    w->done++;
    if (w->cb) w->cb(w->done, w->total, w->ctx);
    return rc;
}

findings_t *scan_run(const char *root, const scan_opts *opts,
                     scan_progress_cb progress, void *pctx)
{
    scan_opts def = scan_default_opts();
    const scan_opts *o = opts ? opts : &def;

    size_t nrules = 0;
    const rule_t *rules = rules_init(&nrules);
    if (!rules) return NULL;

    findings_t *fs = calloc(1, sizeof(*fs));
    if (!fs) return NULL;

    scan_ctx sc = { fs, rules, nrules, o };

    size_t errors = 0;
    if (progress) {
        progress_wrap w = { progress, pctx,
                            walk_count(root, &o->walk), 0, &sc };
        walk_tree(root, &o->walk, file_cb_progress, &w, NULL, &errors);
    } else {
        walk_tree(root, &o->walk, file_cb, &sc, NULL, &errors);
    }
    fs->errors = errors;
    return fs;
}

void findings_free(findings_t *fs)
{
    if (!fs) return;
    finding_t *f = fs->head;
    while (f) { finding_t *n = f->next; free(f); f = n; }
    free(fs);
}
