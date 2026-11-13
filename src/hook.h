#ifndef FNPATCH_HOOK_H
#define FNPATCH_HOOK_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

/*
 * arm64 inline hook.
 *
 * Patch:      ldr x16,#8 ; br x16 ; .quad handler   (16 bytes)
 * Trampoline: relocated original 4 instructions ; ldr x16,#8 ; br x16 ; .quad target+16
 *
 * Only four instructions are displaced, so the first 16 bytes must be relocatable.
 * ADRP, B.cond, CBZ/CBNZ, TBZ/TBNZ and LDR-literal are rewritten for the new
 * address; a direct B/BL in the prologue is refused rather than miscompiled.
 */
typedef struct fn_hook {
    void     *target;
    void     *trampoline;
    uint32_t  saved[4];
    uint32_t  saved_count;
} fn_hook;

/* mprotect a code page writable via COW (works on shared-cache pages). */
bool fn_vm_writable(void *addr, size_t len);

/* Force `mov w0,#value ; ret` / `ret` over the entry point. */
bool fn_patch_ret_w0(void *target, int32_t value);
bool fn_patch_ret_void(void *target);

/* Redirect target to handler. Returns NULL if the prologue cannot be relocated. */
fn_hook *fn_hook_inline(void *target, void *handler, void **trampoline_out);

/* dlsym on the default handle; NULL when the symbol is absent. */
void *fn_sym(const char *name);

/* Slide and header of the main executable. */
uintptr_t fn_main_slide(void);
void     *fn_main_header(void);

#endif
