#include "modules.h"
#include "hook.h"
#include "log.h"
#include "config.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/*
 * Two jobs:
 *   1. nothing may open the dylib itself, so path probes come back ENOENT
 *   2. log every filesystem probe that looks like an integrity check, so the
 *      kick function's neighbourhood shows up in FnPatch.log
 */

#define FN_MAX_LOG_HITS 4000

static const char *const g_hide_paths[] = {
    "FnPatch.dylib",
    "CydiaSubstrate",
    "Substrate",
    "libhooker",
    "ellekit",
};

static const char *const g_watch[] = {
    "FortniteClient-IOS-Shipping",
    "Info.plist",
    "cookeddata",
    "Assets.car",
    "CodeResources",
    "_CodeSignature",
    "SC_Info",
    "EOSSDK",
    "Frameworks",
    ".upl",
    ".upf",
    "Manifest",
    "configrules",
    "uecommandline",
    "cyan.entitlements",
};

static int g_hits;

static bool is_hidden(const char *path)
{
    for (size_t i = 0; i < sizeof(g_hide_paths) / sizeof(g_hide_paths[0]); i++) {
        if (strstr(path, g_hide_paths[i])) {
            return true;
        }
    }
    return false;
}

static void watch(const char *func, const char *path)
{
    if (!path || g_hits >= FN_MAX_LOG_HITS) {
        return;
    }
    for (size_t i = 0; i < sizeof(g_watch) / sizeof(g_watch[0]); i++) {
        if (strstr(path, g_watch[i])) {
            g_hits++;
            FNLOG("fs: %s(%s)", func, path);
            return;
        }
    }
}

typedef int (*open_t)(const char *, int, ...);
typedef int (*openat_t)(int, const char *, int, ...);
typedef int (*stat_t)(const char *, struct stat *);
typedef int (*access_t)(const char *, int);
typedef FILE *(*fopen_t)(const char *, const char *);

static open_t   g_real_open;
static openat_t g_real_openat;
static stat_t   g_real_stat;
static stat_t   g_real_lstat;
static access_t g_real_access;
static fopen_t  g_real_fopen;

static int hook_open(const char *path, int flags, mode_t mode)
{
    if (path && is_hidden(path)) {
        FNLOG("fs: open(%s) denied", path);
        errno = ENOENT;
        return -1;
    }
    watch("open", path);
    return g_real_open ? g_real_open(path, flags, mode) : -1;
}

static int hook_openat(int dirfd, const char *path, int flags, mode_t mode)
{
    if (path && is_hidden(path)) {
        FNLOG("fs: openat(%s) denied", path);
        errno = ENOENT;
        return -1;
    }
    watch("openat", path);
    return g_real_openat ? g_real_openat(dirfd, path, flags, mode) : -1;
}

static int hook_stat(const char *path, struct stat *buf)
{
    if (path && is_hidden(path)) {
        errno = ENOENT;
        return -1;
    }
    watch("stat", path);
    return g_real_stat ? g_real_stat(path, buf) : -1;
}

static int hook_lstat(const char *path, struct stat *buf)
{
    if (path && is_hidden(path)) {
        errno = ENOENT;
        return -1;
    }
    watch("lstat", path);
    return g_real_lstat ? g_real_lstat(path, buf) : -1;
}

static int hook_access(const char *path, int mode)
{
    if (path && is_hidden(path)) {
        errno = ENOENT;
        return -1;
    }
    watch("access", path);
    return g_real_access ? g_real_access(path, mode) : -1;
}

static FILE *hook_fopen(const char *path, const char *mode)
{
    if (path && is_hidden(path)) {
        errno = ENOENT;
        return NULL;
    }
    watch("fopen", path);
    return g_real_fopen ? g_real_fopen(path, mode) : NULL;
}

void mod_fileint_install(void)
{
    if (!fn_cfg_flag("fileint", 1)) {
        return;
    }

    struct {
        const char *name;
        void       *handler;
        void      **real;
    } table[] = {
        { "open",    (void *)hook_open,    (void **)&g_real_open   },
        { "openat",  (void *)hook_openat,  (void **)&g_real_openat },
        { "stat",    (void *)hook_stat,    (void **)&g_real_stat   },
        { "lstat",   (void *)hook_lstat,   (void **)&g_real_lstat  },
        { "access",  (void *)hook_access,  (void **)&g_real_access },
        { "fopen",   (void *)hook_fopen,   (void **)&g_real_fopen  },
    };

    for (size_t i = 0; i < sizeof(table) / sizeof(table[0]); i++) {
        void *sym = fn_sym(table[i].name);
        if (!sym) {
            FNLOG("fileint: %s absent", table[i].name);
            continue;
        }
        if (!fn_hook_inline(sym, table[i].handler, table[i].real)) {
            FNLOG("fileint: %s hook failed", table[i].name);
        } else {
            FNLOG("fileint: %s hooked", table[i].name);
        }
    }
}
