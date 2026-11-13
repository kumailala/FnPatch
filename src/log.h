#ifndef FNPATCH_LOG_H
#define FNPATCH_LOG_H

#include <stdbool.h>

void fn_log_init(void);
void fn_log(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

/*
 * Config lives at $HOME/Documents/FnPatch.config, one `key=value` per line.
 * A missing file means defaults. Values are cached after the first read.
 */
const char *fn_cfg_get(const char *key, const char *fallback);
int         fn_cfg_flag(const char *key, int fallback);

#endif
