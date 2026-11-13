#include "modules.h"
#include "hook.h"
#include "log.h"
#include "config.h"

#include <errno.h>
#include <dirent.h>
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

/*
 * Names that are filtered out of directory listings but still open normally.
 * The diag folder has to stay writable for us, it just should not be visible
 * to anything enumerating Documents.
 */
static const char *const g_hide_from_listing[] = {
    "FnPatch.dylib",
    "FnDiag",
    "FnPatch.log",
    "FnPatch.log.1",
    "FnPatch.config",
    "embedded.mobileprovision",
};

/*
 * An App Store build has no embedded provisioning profile, a sideloaded one
 * does. Denying it makes the container look like the store build instead of
 * like a re-signed copy, and nothing in the game reads it at runtime.
 */
static bool g_hide_provision = true;

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
    if (!path) {
        return false;
    }
    for (size_t i = 0; i < sizeof(g_hide_paths) / sizeof(g_hide_paths[0]); i++) {
        if (strstr(path, g_hide_paths[i])) {
            return true;
        }
    }
    if (g_hide_provision && strstr(path, "embedded.mobileprovision")) {
        return true;
    }
    return false;
}

static bool is_hidden_listing(const char *name)
{
    if (!name) {
        return false;
    }
    for (size_t i = 0;
         i < sizeof(g_hide_from_listing) / sizeof(g_hide_from_listing[0]); i++) {
        if (strcmp(name, g_hide_from_listing[i]) == 0) {
            return true;
        }
    }
    return false;
}

static void watch(const char *func, const char *path, void *caller)
{
    if (!path || g_hits >= FN_MAX_LOG_HITS) {
        return;
    }
    for (size_t i = 0; i < sizeof(g_watch) / sizeof(g_watch[0]); i++) {
        if (strstr(path, g_watch[i])) {
            g_hits++;
            uintptr_t pc   = (uintptr_t)caller;
            uintptr_t base = (uintptr_t)fn_main_header();
            FNLOG("fs: %s(%s) caller=+0x%llx", func, path,
                  (unsigned long long)(pc - base));
            return;
        }
    }
}

typedef int (*open_t)(const char *, int, ...);
typedef int (*openat_t)(int, const char *, int, ...);
typedef int (*stat_t)(const char *, struct stat *);
typedef int (*access_t)(const char *, int);
typedef FILE *(*fopen_t)(const char *, const char *);
typedef struct dirent *(*readdir_t)(DIR *);
typedef int (*readdir_r_t)(DIR *, struct dirent *, struct dirent **);

static open_t   g_real_open;
static openat_t g_real_openat;
static stat_t   g_real_stat;
static stat_t   g_real_lstat;
static access_t g_real_access;
static fopen_t  g_real_fopen;
static readdir_t g_real_readdir;
static readdir_r_t g_real_readdir_r;

static int hook_open(const char *path, int flags, mode_t mode)
{
    if (path && is_hidden(path)) {
        FNLOG("fs: open(%s) denied", path);
        errno = ENOENT;
        return -1;
    }
    watch("open", path, __builtin_return_address(0));
    return g_real_open ? g_real_open(path, flags, mode) : -1;
}

static int hook_openat(int dirfd, const char *path, int flags, mode_t mode)
{
    if (path && is_hidden(path)) {
        FNLOG("fs: openat(%s) denied", path);
        errno = ENOENT;
        return -1;
    }
    watch("openat", path, __builtin_return_address(0));
    return g_real_openat ? g_real_openat(dirfd, path, flags, mode) : -1;
}

static int hook_stat(const char *path, struct stat *buf)
{
    if (path && is_hidden(path)) {
        errno = ENOENT;
        return -1;
    }
    watch("stat", path, __builtin_return_address(0));
    return g_real_stat ? g_real_stat(path, buf) : -1;
}

static int hook_lstat(const char *path, struct stat *buf)
{
    if (path && is_hidden(path)) {
        errno = ENOENT;
        return -1;
    }
    watch("lstat", path, __builtin_return_address(0));
    return g_real_lstat ? g_real_lstat(path, buf) : -1;
}

static int hook_access(const char *path, int mode)
{
    if (path && is_hidden(path)) {
        errno = ENOENT;
        return -1;
    }
    watch("access", path, __builtin_return_address(0));
    return g_real_access ? g_real_access(path, mode) : -1;
}

static FILE *hook_fopen(const char *path, const char *mode)
{
    if (path && is_hidden(path)) {
        errno = ENOENT;
        return NULL;
    }
    watch("fopen", path, __builtin_return_address(0));
    return g_real_fopen ? g_real_fopen(path, mode) : NULL;
}

static struct dirent *hook_readdir(DIR *dirp)
{
    if (!g_real_readdir) {
        errno = EBADF;
        return NULL;
    }
    struct dirent *ent;
    int skipped = 0;
    while ((ent = g_real_readdir(dirp)) != NULL) {
        if (is_hidden_listing(ent->d_name)) {
            skipped++;
            continue;
        }
        break;
    }
    if (skipped) {
        FNLOG("fs: readdir hid %d entries", skipped);
    }
    return ent;
}

static int hook_readdir_r(DIR *dirp, struct dirent *entry, struct dirent **result)
{
    if (!g_real_readdir_r) {
        return EBADF;
    }
    for (;;) {
        struct dirent *out = NULL;
        int rc = g_real_readdir_r(dirp, entry, &out);
        if (rc != 0) {
            if (result) {
                *result = out;
            }
            return rc;
        }
        if (!out || !is_hidden_listing(out->d_name)) {
            if (result) {
                *result = out;
            }
            return 0;
        }
        FNLOG("fs: readdir_r hid %s", out->d_name);
    }
}

void mod_fileint_install(void)
{
    if (!fn_cfg_flag("fileint", 1)) {
        return;
    }

    g_hide_provision = fn_cfg_flag("hide_provision", 1) != 0;
    FNLOG("fileint: hide_provision=%d", g_hide_provision ? 1 : 0);

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
        { "readdir", (void *)hook_readdir, (void **)&g_real_readdir },
        { "readdir_r", (void *)hook_readdir_r, (void **)&g_real_readdir_r },
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
