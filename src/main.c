#include "scan.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#ifndef VERSION
#define VERSION "0.0.0"
#endif

/* ANSI colour helpers (suppressed when stdout is not a TTY or --no-color). */
static int use_color = 1;
static const char *C_RESET = "\033[0m";

static const char *sev_color(severity_t s)
{
    if (!use_color) return "";
    switch (s) {
        case SEV_CRITICAL: return "\033[1;31m";  /* bold red    */
        case SEV_HIGH:     return "\033[31m";     /* red         */
        case SEV_MEDIUM:   return "\033[33m";     /* yellow      */
        default:           return "\033[36m";     /* cyan        */
    }
}

static void usage(const char *prog)
{
    printf(
        "mole %s - recursive secrets scanner (entropy + regex signatures)\n\n"
        "Usage: %s [options] [PATH]\n\n"
        "  PATH                  directory (or omit for current dir)\n\n"
        "Options:\n"
        "  -e, --min-entropy N   Shannon bits/char gate for generic matches\n"
        "  -t, --entropy-thresh N  threshold for the standalone entropy scan (default 4.3)\n"
        "  -E, --no-entropy      disable the standalone high-entropy blob scan\n"
        "  -a, --all             do not skip VCS/vendor dirs (.git, node_modules, ...)\n"
        "  -H, --skip-hidden     skip dot-files and dot-directories\n"
        "  -s, --severity LEVEL  only report at/above LEVEL (low|medium|high|critical)\n"
        "      --no-color        disable coloured output\n"
        "  -h, --help            show this help\n"
        "  -v, --version         show version\n\n"
        "Exit status: 0 = clean, 1 = findings, 2 = error.\n",
        VERSION, prog);
}

static severity_t parse_severity(const char *s)
{
    if (!strcasecmp(s, "critical")) return SEV_CRITICAL;
    if (!strcasecmp(s, "high"))     return SEV_HIGH;
    if (!strcasecmp(s, "medium"))   return SEV_MEDIUM;
    return SEV_LOW;
}

int main(int argc, char **argv)
{
    scan_opts opts = scan_default_opts();
    const char *root = ".";
    severity_t min_sev = SEV_LOW;

    if (!isatty(STDOUT_FILENO)) use_color = 0;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "-h") || !strcmp(a, "--help")) { usage(argv[0]); return 0; }
        else if (!strcmp(a, "-v") || !strcmp(a, "--version")) {
            printf("mole %s\n", VERSION); return 0;
        }
        else if (!strcmp(a, "-e") || !strcmp(a, "--min-entropy")) {
            if (++i >= argc) { fprintf(stderr, "mole: %s needs a value\n", a); return 2; }
            opts.min_entropy_generic = atof(argv[i]);
        }
        else if (!strcmp(a, "-t") || !strcmp(a, "--entropy-thresh")) {
            if (++i >= argc) { fprintf(stderr, "mole: %s needs a value\n", a); return 2; }
            opts.entropy_threshold = atof(argv[i]);
        }
        else if (!strcmp(a, "-E") || !strcmp(a, "--no-entropy")) opts.entropy_scan = 0;
        else if (!strcmp(a, "-a") || !strcmp(a, "--all"))        opts.walk.skip_vcs = 0;
        else if (!strcmp(a, "-H") || !strcmp(a, "--skip-hidden")) opts.walk.skip_hidden = 1;
        else if (!strcmp(a, "-s") || !strcmp(a, "--severity")) {
            if (++i >= argc) { fprintf(stderr, "mole: %s needs a value\n", a); return 2; }
            min_sev = parse_severity(argv[i]);
        }
        else if (!strcmp(a, "--no-color")) use_color = 0;
        else if (a[0] == '-') {
            fprintf(stderr, "mole: unknown option '%s'\n", a);
            usage(argv[0]);
            return 2;
        }
        else root = a;
    }

    findings_t *fs = scan_run(root, &opts, NULL, NULL);
    if (!fs) { fprintf(stderr, "mole: scan failed\n"); return 2; }

    size_t shown = 0;
    size_t by_sev[4] = {0};
    for (finding_t *f = fs->head; f; f = f->next) {
        if (f->severity < min_sev) continue;
        shown++;
        by_sev[f->severity]++;
        printf("%s%-8s%s %s:%ld\n",
               sev_color(f->severity), severity_name(f->severity),
               use_color ? C_RESET : "", f->path, f->line);
        printf("    rule    : %s\n", f->rule);
        printf("    secret  : %s  (entropy %.2f bits/char)\n",
               f->redacted, f->entropy);
        printf("    context : %s\n\n", f->preview);
    }

    fprintf(stderr,
        "Scanned %zu files (%zu skipped, %zu errors). "
        "%zu finding(s) shown: %zu critical, %zu high, %zu medium, %zu low.\n",
        fs->files_scanned, fs->files_skipped, fs->errors, shown,
        by_sev[SEV_CRITICAL], by_sev[SEV_HIGH], by_sev[SEV_MEDIUM], by_sev[SEV_LOW]);

    int had_findings = (shown > 0);
    findings_free(fs);
    rules_free();
    return had_findings ? 1 : 0;
}
