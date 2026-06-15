#ifndef MOLE_WALK_H
#define MOLE_WALK_H

#include <stddef.h>

#define MOLE_MAX_PATH 4096

/* Recursive directory walker, adapted from syshash's scan.c.
 *
 * As in syshash we use lstat() so symbolic links are never followed (no loops,
 * no escaping the tree) and only real directories and regular files are
 * visited. Rather than hashing each file we hand it to a caller-supplied
 * callback, which reads and greps its contents. */

typedef struct {
    int    skip_vcs;       /* skip .git/.svn/.hg and common vendor dirs */
    int    skip_hidden;    /* skip dot-files and dot-directories         */
    size_t max_file_size;  /* skip regular files larger than this (0 = no limit) */
} walk_opts;

/* Sensible defaults: skip VCS/vendor noise, scan hidden files, cap at 8 MiB. */
walk_opts walk_default_opts(void);

/* Called once per regular file. `full` is usable with open(); `rel` is
 * relative to `root` (no leading "./"). Return non-zero to abort the walk. */
typedef int (*walk_cb)(const char *full, const char *rel, void *ctx);

/* Walk `root` (defaults to "." if NULL/empty), invoking `cb` per file.
 * *files_out / *errors_out (may be NULL) receive counts. Returns 0, or -1 if
 * the callback aborted. */
int walk_tree(const char *root, const walk_opts *opts,
              walk_cb cb, void *ctx, size_t *files_out, size_t *errors_out);

/* Fast pre-count of files that would be visited (readdir + lstat only),
 * for sizing a progress bar before the slow content pass. */
size_t walk_count(const char *root, const walk_opts *opts);

#endif /* MOLE_WALK_H */
