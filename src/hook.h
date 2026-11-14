#ifndef FNPATCH_HOOK_H
#define FNPATCH_HOOK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Page protection and image addresses. Nothing here patches code.
 *
 * Inline hooking was removed in 1.1.0. On the target kernel a signed code page
 * can be made writable but execute cannot be put back: R|X, R|W|X and
 * mprotect(PROT_EXEC) all return KERN_PROTECTION_FAILURE. A page treated that
 * way is left writable and non-executable and faults on the next branch into
 * it. That is what killed the 1.0.1 build, and there is no way to undo it in
 * the process, so the only safe number of code writes is zero.
 *
 * What is left is the data side: making a data page writable long enough to
 * swap a pointer, and putting it back to read-only.
 */

/* Make a page writable through VM_PROT_COPY. Returns false if refused. */
bool fn_vm_writable(void *addr, size_t len);

/* Put a code page back to read+execute. Returns false when the kernel refuses;
 * a false here means the page is now writable and must never be executed. */
bool fn_make_executable_ok(void *addr, size_t len);

/* As above, result ignored. Only for pages that hold no code. */
void fn_make_executable(void *addr, size_t len);

/* Put a data page back to read-only. */
void fn_make_readonly(void *addr, size_t len);

/* Header and slide of the main executable. */
void     *fn_main_header(void);
uintptr_t fn_main_slide(void);

#endif
