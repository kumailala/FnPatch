#include "log.h"
#include "config.h"

#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <time.h>

#define FN_CFG_MAX_LINES 256
#define FN_CFG_LINE_LEN  256

static pthread_mutex_t g_log_lock = PTHREAD_MUTEX_INITIALIZER;
static char            g_log_path[512];
static char            g_cfg_path[512];

/*
 * fopen is hooked by mod_fileint, which logs through here. Without this the
 * logger would re-enter itself through the hook and blow the stack.
 */
static __thread int g_in_log;

static struct { char key[64]; char val[384]; } g_cfg[FN_CFG_MAX_LINES];
static int  g_cfg_count = -1;

static const char *home_dir(void)
{
    const char *h = getenv("HOME");
    return h ? h : "/tmp";
}

/*
 * Everything visible to a human lives in Documents/FnDiag: the app's Documents
 * folder shows up in the Files app for this bundle, so the log and the config
 * are one tap away instead of needing a cable.
 */
static void init_paths(void)
{
    char dir[480];
    snprintf(dir, sizeof(dir), "%s/Documents/FnDiag", home_dir());
    mkdir(dir, 0755);
    snprintf(g_log_path, sizeof(g_log_path), "%s/FnPatch.log", dir);
    snprintf(g_cfg_path, sizeof(g_cfg_path), "%s/FnPatch.config", dir);
}

const char *fn_log_path(void)
{
    if (!g_log_path[0]) {
        init_paths();
    }
    return g_log_path;
}

const char *fn_cfg_path(void)
{
    if (!g_cfg_path[0]) {
        init_paths();
    }
    return g_cfg_path;
}

static void cfg_load(void)
{
    if (g_cfg_count >= 0) {
        return;
    }
    g_cfg_count = 0;

    char path[512];
    snprintf(path, sizeof(path), "%s", fn_cfg_path());

    FILE *f = fopen(path, "r");
    if (!f) {
        /* Older builds wrote the config one level up. */
        snprintf(path, sizeof(path), "%s/Documents/FnPatch.config", home_dir());
        f = fopen(path, "r");
    }
    if (!f) {
        return;
    }
    char line[FN_CFG_LINE_LEN];
    while (fgets(line, sizeof(line), f) && g_cfg_count < FN_CFG_MAX_LINES) {
        char *nl = strpbrk(line, "\r\n");
        if (nl) {
            *nl = '\0';
        }
        char *hash = strchr(line, '#');
        if (hash) {
            *hash = '\0';
        }
        char *eq = strchr(line, '=');
        if (!eq) {
            continue;
        }
        *eq = '\0';
        char *k = line;
        char *v = eq + 1;
        while (*k == ' ' || *k == '\t') k++;
        while (*v == ' ' || *v == '\t') v++;
        char *ke = eq - 1;
        while (ke >= k && (*ke == ' ' || *ke == '\t')) *ke-- = '\0';
        if (!*k) {
            continue;
        }
        snprintf(g_cfg[g_cfg_count].key, sizeof(g_cfg[0].key), "%s", k);
        snprintf(g_cfg[g_cfg_count].val, sizeof(g_cfg[0].val), "%s", v);
        g_cfg_count++;
    }
    fclose(f);
}

const char *fn_cfg_get(const char *key, const char *fallback)
{
    cfg_load();
    for (int i = 0; i < g_cfg_count; i++) {
        if (strcmp(g_cfg[i].key, key) == 0) {
            return g_cfg[i].val;
        }
    }
    return fallback;
}

int fn_cfg_flag(const char *key, int fallback)
{    const char *v = fn_cfg_get(key, NULL);
    if (!v) {
        return fallback;
    }
    if (strcmp(v, "1") == 0 || strcasecmp(v, "true") == 0 ||
        strcasecmp(v, "yes") == 0 || strcasecmp(v, "on") == 0) {
        return 1;
    }
    if (strcmp(v, "0") == 0 || strcasecmp(v, "false") == 0 ||
        strcasecmp(v, "no") == 0 || strcasecmp(v, "off") == 0) {
        return 0;
    }
    return atoi(v);
}

/* Drop the cache so the next read re-parses the file. Used after the defaults
 * are rewritten, so a stale config cannot survive an update. */
void fn_cfg_reload(void)
{
    g_cfg_count = -1;
}

void fn_log_init(void)
{
    /* fn_log_path() creates Documents/FnDiag and fills g_log_path. */
    (void)fn_log_path();

    /* Keep the previous run, truncate this one. */
    char prev[520];
    snprintf(prev, sizeof(prev), "%s.1", g_log_path);
    rename(g_log_path, prev);

    FILE *f = fopen(g_log_path, "w");
    if (f) {
        time_t now = time(NULL);
        struct tm tm;
        localtime_r(&now, &tm);
        fprintf(f, "=== FnPatch %s  %04d-%02d-%02d %02d:%02d:%02d ===\n",
                FN_PATCH_VERSION, tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                tm.tm_hour, tm.tm_min, tm.tm_sec);
        fclose(f);
    }
}
void fn_log(const char *fmt, ...)
{
    if (g_in_log) {
        return;
    }
    g_in_log = 1;

    va_list ap;
    va_start(ap, fmt);
    char msg[1024];
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    pthread_mutex_lock(&g_log_lock);
    if (!g_log_path[0]) {
        fn_log_init();
    }
    FILE *f = fopen(g_log_path, "a");
    if (f) {
        fprintf(f, "%s\n", msg);
        fclose(f);
    }
    pthread_mutex_unlock(&g_log_lock);

    g_in_log = 0;
}
