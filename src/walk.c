#include "walk.h"
#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>

walk_opts walk_default_opts(void)
{
    walk_opts o;
    o.skip_vcs       = 1;
    o.skip_hidden    = 0;
    o.max_file_size  = 8u * 1024u * 1024u;   /* 8 MiB */
    return o;
}

/* Directory names that are almost always noise for a secrets scan and that
 * would otherwise dominate the walk (object stores, dependency trees). */
static int is_vcs_or_vendor(const char *name)
{
    static const char *skip[] = {
        ".git", ".svn", ".hg", ".bzr",
        "node_modules", "vendor", ".venv", "venv",
        "__pycache__", ".mypy_cache", ".tox", "target",
        NULL
    };
    for (int i = 0; skip[i]; i++)
        if (strcmp(name, skip[i]) == 0) return 1;
    return 0;
}

static int should_skip_dir(const char *name, const walk_opts *o)
{
    if (o->skip_vcs && is_vcs_or_vendor(name)) return 1;
    if (o->skip_hidden && name[0] == '.')      return 1;
    return 0;
}

static int walk(const char *prefix, const char *dir,
                const walk_opts *o, walk_cb cb, void *ctx,
                size_t *files, size_t *errors)
{
    DIR *dp = opendir(dir);
    if (!dp) {
        fprintf(stderr, "  warning: cannot open dir: %s (%s)\n",
                dir, strerror(errno));
        (*errors)++;
        return 0;
    }

    struct dirent *de;
    while ((de = readdir(dp)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;

        char full[MOLE_MAX_PATH];
        if (snprintf(full, sizeof(full), "%s/%s", dir, de->d_name)
                >= (int)sizeof(full)) {
            (*errors)++;
            continue;
        }

        char rel[MOLE_MAX_PATH];
        if (prefix[0])
            snprintf(rel, sizeof(rel), "%s/%s", prefix, de->d_name);
        else
            snprintf(rel, sizeof(rel), "%s", de->d_name);

        struct stat st;
        if (lstat(full, &st) != 0) {
            (*errors)++;
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            if (should_skip_dir(de->d_name, o))
                continue;
            if (walk(rel, full, o, cb, ctx, files, errors) != 0) {
                closedir(dp);
                return -1;
            }
        } else if (S_ISREG(st.st_mode)) {
            if (o->skip_hidden && de->d_name[0] == '.')
                continue;
            if (o->max_file_size && (size_t)st.st_size > o->max_file_size)
                continue;
            (*files)++;
            if (cb(full, rel, ctx) != 0) {
                closedir(dp);
                return -1;
            }
        }
    }
    closedir(dp);
    return 0;
}

int walk_tree(const char *root, const walk_opts *opts,
              walk_cb cb, void *ctx, size_t *files_out, size_t *errors_out)
{
    walk_opts def = walk_default_opts();
    const walk_opts *o = opts ? opts : &def;
    const char *path = (root && root[0]) ? root : ".";
    size_t files = 0, errors = 0;

    /* Allow a single regular file as the root, not just a directory. */
    struct stat st;
    if (lstat(path, &st) == 0 && S_ISREG(st.st_mode)) {
        const char *base = strrchr(path, '/');
        base = base ? base + 1 : path;
        files++;
        int crc = cb(path, base, ctx);
        if (files_out)  *files_out  = files;
        if (errors_out) *errors_out = 0;
        return crc ? -1 : 0;
    }

    int rc = walk("", path, o, cb, ctx, &files, &errors);
    if (files_out)  *files_out  = files;
    if (errors_out) *errors_out = errors;
    return rc;
}

static int count_cb(const char *full, const char *rel, void *ctx)
{
    (void)full; (void)rel;
    (*(size_t *)ctx)++;
    return 0;
}

size_t walk_count(const char *root, const walk_opts *opts)
{
    size_t n = 0;
    walk_tree(root, opts, count_cb, &n, NULL, NULL);
    return n;
}
