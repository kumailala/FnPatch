#include "modules.h"
#include "hook.h"
#include "log.h"
#include "config.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/*
 * Escape hatch for the addresses that cannot be found by symbol: once
 * FnPatch.log shows which probe fires, its caller's address goes in
 * FnPatch.config and gets neutralised at boot.
 *
 *   ret0    = 0x1a2b3c,0x4d5e6f      mov w0,#0 ; ret
 *   ret1    = 0x1a2b3c               mov w0,#1 ; ret
 *   retvoid = 0x1a2b3c               ret
 *
 * Offsets are relative to the main executable's Mach-O header.
 */

#define FN_MAX_OFFSETS 64

static void apply_list(const char *key, int mode)
{
    const char *raw = fn_cfg_get(key, NULL);
    if (!raw) {
        return;
    }

    char buf[1024];
    snprintf(buf, sizeof(buf), "%s", raw);

    uintptr_t base = (uintptr_t)fn_main_header();
    char *save = NULL;
    int applied = 0;

    for (char *tok = strtok_r(buf, ",; ", &save); tok;
         tok = strtok_r(NULL, ",; ", &save)) {
        char *end = NULL;
        unsigned long long parsed = strtoull(tok, &end, 0);
        if (end == tok || parsed == 0) {
            FNLOG("offsets: %s entry '%s' is not an offset, skipped", key, tok);
            continue;
        }
        uintptr_t off = (uintptr_t)parsed;
        void *addr = (void *)(base + off);

        bool ok = false;
        switch (mode) {
            case 0: ok = fn_patch_ret_w0(addr, 0); break;
            case 1: ok = fn_patch_ret_w0(addr, 1); break;
            default: ok = fn_patch_ret_void(addr); break;
        }
        FNLOG("offsets: %s '%s' -> %p (header+0x%llx) %s", key, tok, addr,
              (unsigned long long)off, ok ? "patched" : "failed");
        applied += ok ? 1 : 0;
    }
    FNLOG("offsets: %s applied %d", key, applied);
    (void)applied;
}

void mod_offsets_install(void)
{
    if (!fn_cfg_flag("offsets", 1)) {
        return;
    }
    apply_list("ret0", 0);
    apply_list("ret1", 1);
    apply_list("retvoid", 2);
}
