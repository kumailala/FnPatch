#ifndef FNPATCH_LOG_H
#define FNPATCH_LOG_H

#include <stdbool.h>

void fn_log_init(void);
void fn_log(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

/* Both live in $HOME/Documents/FnDiag, which is visible in the Files app. */
const char *fn_log_path(void);
const char *fn_cfg_path(void);

#define FNLOG(...) fn_log(__VA_ARGS__)

/*
 * Config lives at $HOME/Documents/FnDiag/FnPatch.config, one `key=value` per
 * line. A missing file means defaults. Values are cached after the first read.
 */
const char *fn_cfg_get(const char *key, const char *fallback);
int         fn_cfg_flag(const char *key, int fallback);

/* Invalidate the cache; the next read re-parses Documents/FnDiag/FnPatch.config. */
void        fn_cfg_reload(void);

#endif
