#include "hook.h"
#include "log.h"

#include <dlfcn.h>
#include <mach/mach.h>
#include <mach/mach_host.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <libkern/OSCacheControl.h>

#define A64_LDR_X16_8   0x58000050u
#define A64_BR_X16      0xD61F0200u
#define A64_RET         0xD65F03C0u
#define A64_MOV_W0_0    0x52800000u

static bool is_adrp(uint32_t i)      { return (i & 0x9F000000u) == 0x90000000u; }
static bool is_ret(uint32_t i)       { return (i & 0xFFFFFC1Fu) == 0xD65F0000u; }
static bool is_b_uncond(uint32_t i)  { return (i & 0x7C000000u) == 0x14000000u; }
static bool is_bcond(uint32_t i)     { return (i & 0xFF000010u) == 0x54000000u; }
static bool is_cbz(uint32_t i)       { return (i & 0x7E000000u) == 0x34000000u; }
static bool is_tbz(uint32_t i)       { return (i & 0x7E000000u) == 0x36000000u; }
static bool is_ldr_lit(uint32_t i)   { return (i & 0x3B000000u) == 0x18000000u; }

static size_t page_size_cached(void)
{
    static size_t cached;
    if (!cached) {
        int ps = getpagesize();
        cached = ps > 0 ? (size_t)ps : 16384;
    }
    return cached;
}

/* Defined below; used by the patch helpers above it. */
static bool addr_in_signed_image(const void *p);
static bool code_patch_supported(void);

bool fn_vm_writable(void *addr, size_t len)
{
    size_t ps = page_size_cached();
    uintptr_t page = (uintptr_t)addr & ~(uintptr_t)(ps - 1);
    size_t    off  = (uintptr_t)addr - page;
    size_t    size = ((off + len + ps - 1) / ps) * ps;

    kern_return_t kr = vm_protect(mach_task_self(), page, size, false,
                                  VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr != KERN_SUCCESS) {
        FNLOG("vm_protect failed at %p (0x%x)", addr, kr);
        return false;
    }
    return true;
}

/*
 * Restore read+execute after a patch.
 *
 * This used to be a single vm_protect(R|X) whose failure was logged and then
 * ignored. On this device that call returns KERN_PROTECTION_FAILURE (0x2) for
 * any page that has just been made writable with VM_PROT_COPY, which leaves
 * the page writable and NON-EXECUTABLE. The next branch into it is a SIGSEGV
 * with no useful backtrace, and it is what killed the 10:57 build: the
 * trampoline cave shares a page with our own code, so the first inline hook
 * took the dylib down with it.
 *
 * Three attempts, in order of how much we want them:
 *   1. R|X              - correct.
 *   2. R|W|X            - keeps execute. Writability is a smaller sin than a
 *                         non-executable code page, and on a sideloaded
 *                         (get-task-allow) process the kernel usually allows
 *                         this when it refuses step 1.
 *   3. mprotect(P|E)    - different path to the same protection.
 * Only if all three fail is the page left writable, and that is logged loudly
 * because it is a guaranteed crash on the next call into the page.
 */
void fn_make_executable(void *addr, size_t len)
{
    (void)fn_make_executable_ok(addr, len);
}

bool fn_make_executable_ok(void *addr, size_t len)
{
    size_t ps = page_size_cached();
    uintptr_t page = (uintptr_t)addr & ~(uintptr_t)(ps - 1);
    size_t    off  = (uintptr_t)addr - page;
    size_t    size = ((off + len + ps - 1) / ps) * ps;

    kern_return_t kr = vm_protect(mach_task_self(), page, size, false,
                                  VM_PROT_READ | VM_PROT_EXECUTE);
    if (kr == KERN_SUCCESS) {
        return true;
    }

    kern_return_t krw = vm_protect(mach_task_self(), page, size, false,
                                   VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
    if (krw == KERN_SUCCESS) {
        FNLOG("make_executable: %p kept RWX (R|X refused 0x%x)", addr, kr);
        return true;
    }

    if (mprotect((void *)page, size, PROT_READ | PROT_EXEC) == 0) {
        FNLOG("make_executable: %p restored via mprotect (vm_protect 0x%x/0x%x)",
              addr, kr, krw);
        return true;
    }

    FNLOG("make_executable: FAILED at %p (0x%x/0x%x) page left writable and "
          "non-executable", addr, kr, krw);
    return false;
}

/*
 * Put a data page back to read-only after a patch. Needed because
 * fn_make_executable adds execute, and __DATA_CONST is a data segment: asking
 * for R|X there is asking the wrong question, and on a stricter kernel the
 * request itself is the failure.
 */
void fn_make_readonly(void *addr, size_t len)
{
    size_t ps = page_size_cached();
    uintptr_t page = (uintptr_t)addr & ~(uintptr_t)(ps - 1);
    size_t    off  = (uintptr_t)addr - page;
    size_t    size = ((off + len + ps - 1) / ps) * ps;

    if (vm_protect(mach_task_self(), page, size, false, VM_PROT_READ) == KERN_SUCCESS) {
        return;
    }
    if (mprotect((void *)page, size, PROT_READ) == 0) {
        return;
    }
    FNLOG("make_readonly: FAILED at %p, page left writable", addr);
}

static void emit_branch(uint32_t *p, uintptr_t dest)
{
    p[0] = A64_LDR_X16_8;
    p[1] = A64_BR_X16;
    memcpy(&p[2], &dest, sizeof(uintptr_t));
}

bool fn_patch_ret_w0(void *target, int32_t value)
{
    if (!target) {
        return false;
    }
    if (!fn_cfg_flag("hook_any", 0) && !addr_in_signed_image(target)) {
        FNLOG("fn_patch_ret_w0: %p refused, not in an app-bundle image", target);
        return false;
    }
    if (!code_patch_supported()) {
        return false;
    }
    uint32_t insn[2];
    if (value >= 0 && value <= 0xFFFF) {
        /* mov w0, #imm16 */
        insn[0] = A64_MOV_W0_0 | ((uint32_t)value << 5);
        insn[1] = A64_RET;
    } else {
        FNLOG("fn_patch_ret_w0: value %d out of movz range", value);
        return false;
    }
    if (!fn_vm_writable(target, sizeof(insn))) {
        return false;
    }
    memcpy(target, insn, sizeof(insn));
    sys_icache_invalidate(target, sizeof(insn));
    fn_make_executable(target, sizeof(insn));
    return true;
}

bool fn_patch_ret_void(void *target)
{
    if (!target) {
        return false;
    }
    if (!fn_cfg_flag("hook_any", 0) && !addr_in_signed_image(target)) {
        FNLOG("fn_patch_ret_void: %p refused, not in an app-bundle image", target);
        return false;
    }
    if (!code_patch_supported()) {
        return false;
    }
    uint32_t insn = A64_RET;
    if (!fn_vm_writable(target, sizeof(insn))) {
        return false;
    }
    memcpy(target, &insn, sizeof(insn));
    sys_icache_invalidate(target, sizeof(insn));
    fn_make_executable(target, sizeof(insn));
    return true;
}

static int64_t decode_imm21(uint32_t i)
{
    int64_t immhi = (i >> 5) & 0x7FFFF;
    int64_t immlo = (i >> 29) & 0x3;
    int64_t v = (immhi << 2) | immlo;
    if (v & (1LL << 20)) {
        v -= (1LL << 21);
    }
    return v;
}

static uint32_t encode_adrp(uint32_t base, int64_t pages)
{
    uint64_t immlo = (uint64_t)pages & 0x3;
    uint64_t immhi = ((uint64_t)pages >> 2) & 0x7FFFF;
    return (base & 0x9F00001Fu) | (uint32_t)(immlo << 29) | (uint32_t)(immhi << 5);
}

static uint32_t encode_imm19(uint32_t base, int64_t slots)
{
    return (base & ~(0x7FFFFu << 5)) | ((uint32_t)(slots & 0x7FFFF) << 5);
}

static uint32_t encode_imm14(uint32_t base, int64_t slots)
{
    return (base & ~(0x3FFFu << 5)) | ((uint32_t)(slots & 0x3FFF) << 5);
}

static bool relocatable(uint32_t i)
{
    if (is_b_uncond(i)) {
        /* BL lands in the 26-bit signed range check; refuse rather than guess. */
        return false;
    }
    return true;
}

static uint32_t relocate(uint32_t i, uintptr_t from, uintptr_t to, bool *ok)
{
    *ok = true;

    if (is_adrp(i)) {
        int64_t  imm   = decode_imm21(i);
        uintptr_t page = (from & ~0xFFFULL) + ((uintptr_t)imm << 12);
        int64_t  delta = ((int64_t)page - (int64_t)(to & ~0xFFFULL)) >> 12;
        if (delta < -(1LL << 20) || delta >= (1LL << 20)) {
            *ok = false;
            return i;
        }
        return encode_adrp(i, delta);
    }
    if (is_bcond(i) || is_cbz(i) || is_ldr_lit(i)) {
        int64_t imm = (int64_t)((i >> 5) & 0x7FFFF);
        if (imm & (1LL << 18)) {
            imm -= (1LL << 19);
        }
        uintptr_t dest  = from + ((uintptr_t)imm * 4);
        int64_t   slots = ((int64_t)dest - (int64_t)to) >> 2;
        if (slots < -(1LL << 18) || slots >= (1LL << 18)) {
            *ok = false;
            return i;
        }
        return encode_imm19(i, slots);
    }
    if (is_tbz(i)) {
        int64_t imm = (int64_t)((i >> 5) & 0x3FFF);
        if (imm & (1LL << 13)) {
            imm -= (1LL << 14);
        }
        uintptr_t dest  = from + ((uintptr_t)imm * 4);
        int64_t   slots = ((int64_t)dest - (int64_t)to) >> 2;
        if (slots < -(1LL << 13) || slots >= (1LL << 13)) {
            *ok = false;
            return i;
        }
        return encode_imm14(i, slots);
    }
    return i;
}

#define FN_HOOK_TRAMP_PAGES 2
#define FN_TRAMP_BYTES     32

/*
 * Trampoline pool inside this dylib's own __TEXT.
 *
 * It is page-aligned and exactly one page so that making it writable, and any
 * failure to make it executable again, cannot take real code down with it. At
 * 32 bytes per trampoline one page holds 512 hooks; the old unaligned 64 KB
 * array shared its first page with fn_hook_inline itself.
 */
#define FN_TRAMP_CAVE_BYTES 16384

__attribute__((used, aligned(16384), section("__TEXT,__text")))
static uint8_t g_tramp_cave[FN_TRAMP_CAVE_BYTES];
static size_t  g_tramp_used;

static void *cave_alloc(size_t size)
{
    size = (size + 15) & ~(size_t)15;
    if (g_tramp_used + size > FN_TRAMP_CAVE_BYTES) {
        return NULL;
    }
    void *p = (void *)(uintptr_t)&g_tramp_cave[g_tramp_used];
    g_tramp_used += size;
    return p;
}

/*
 * One-time capability probe, on the cave page and nowhere else.
 *
 * On this kernel vm_protect(R|W|COPY) succeeds on a signed code page but the
 * reverse request never does: R|X is refused, R|W|X is refused, mprotect(P|E)
 * is refused. A page treated that way is left writable and NON-EXECUTABLE and
 * can never be recovered in that process. Doing that to a page that holds real
 * code is an instant, unrecoverable SIGSEGV — which is exactly what happened
 * to `open()` at 0x114190de0 in the 1.0.1 run.
 *
 * So the question is asked once, on the trampoline cave, which is a whole
 * page of padding that contains no code. If the answer is no, every inline
 * hook and every prologue patch refuses from then on and the app boots with
 * only the data-side work (uacslot), which is the part that fixes the kick.
 */
static bool code_patch_supported(void)
{
    static int cached = -1;
    if (cached >= 0) {
        return cached == 1;
    }

    void *probe = (void *)g_tramp_cave;
    if (!fn_vm_writable(probe, 16)) {
        cached = 0;
        FNLOG("hook: cannot make a code page writable; inline hooks disabled");
        return false;
    }

    bool ok = fn_make_executable_ok(probe, 16);
    cached = ok ? 1 : 0;

    if (ok) {
        FNLOG("hook: inline patching available (probe page %p restored)", probe);
    } else {
        FNLOG("hook: execute CANNOT be restored after a write on this process; "
              "all inline hooks and prologue patches are disabled. uacslot is "
              "unaffected: it swaps a data pointer and never patches code.");
    }
    return ok;
}

bool fn_code_patch_available(void)
{
    return code_patch_supported();
}

static void *alloc_near(uintptr_t target)
{
    const size_t size = FN_HOOK_TRAMP_PAGES * 16384;
    const int64_t reach = 1LL << 27; /* 128 MB, branch-island limit */

    for (int64_t delta = 0x40000; delta < reach; delta += 0x40000) {
        for (int dir = 0; dir < 2; dir++) {
            uintptr_t hint = dir ? (target + delta) : (target - delta);
            if (hint < 0x100000000ULL) {
                continue;
            }
            void *p = mmap((void *)hint, size, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANON, -1, 0);
            if (p == MAP_FAILED) {
                continue;
            }
            int64_t d = (int64_t)(uintptr_t)p - (int64_t)target;
            if (d > -reach && d < reach) {
                return p;
            }
            munmap(p, size);
        }
    }
    FNLOG("alloc_near: no reachable page for %p", (void *)target);
    return NULL;
}

/*
 * Inline hooking is only safe inside an image the installer signed, which on a
 * sideload means the app bundle: the main executable and the frameworks beside
 * it.
 *
 * Everything in /usr/lib and /System lives in the dyld shared cache, which is
 * mapped once and shared by every process on the device. vm_protect with
 * VM_PROT_COPY on one of those pages gives us a private copy, but the copy
 * loses execute on this kernel and the restore path refuses to give it back.
 * That is the second bug in the 10:57 build: mod_codesign walked straight into
 * SecCodeCheckValidity and killed the process inside its own trampoline.
 *
 * The guard is a name test rather than an address test because the shared
 * cache base moves between iOS versions and the app container path does not.
 * `hook_any=1` re-enables the old behaviour for anyone who wants to retest it.
 */
static bool image_is_app_bundle(const char *name)
{
    if (!name) {
        return false;
    }
    return strstr(name, "/Bundle/Application/") != NULL ||
           strstr(name, ".app/") != NULL;
}

static bool addr_in_signed_image(const void *p)
{
    uintptr_t a = (uintptr_t)p;
    uint32_t n = _dyld_image_count();

    for (uint32_t i = 0; i < n; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!image_is_app_bundle(name)) {
            continue;
        }
        const struct mach_header *mh = _dyld_get_image_header(i);
        if (!mh || mh->magic != MH_MAGIC_64) {
            continue;
        }
        uintptr_t slide = (uintptr_t)_dyld_get_image_vmaddr_slide(i);
        const struct mach_header_64 *h = (const struct mach_header_64 *)mh;
        const uint8_t *cmd = (const uint8_t *)h + sizeof(*h);

        for (uint32_t k = 0; k < h->ncmds; k++) {
            const struct load_command *lc = (const struct load_command *)cmd;
            if (lc->cmdsize < sizeof(*lc)) {
                break;
            }
            if (lc->cmd == LC_SEGMENT_64) {
                const struct segment_command_64 *sg =
                    (const struct segment_command_64 *)lc;
                if (strncmp(sg->segname, "__TEXT", sizeof(sg->segname)) == 0) {
                    uintptr_t lo = slide + (uintptr_t)sg->vmaddr;
                    if (a >= lo && a < lo + (uintptr_t)sg->vmsize) {
                        return true;
                    }
                    break;
                }
            }
            cmd += lc->cmdsize;
        }
    }
    return false;
}

fn_hook *fn_hook_inline(void *target, void *handler, void **trampoline_out)
{
    if (!target || !handler) {
        return NULL;
    }

    if (!fn_cfg_flag("hook_any", 0) && !addr_in_signed_image(target)) {
        FNLOG("hook_inline: %p refused, not in an app-bundle image "
              "(shared cache pages lose execute on restore)", target);
        return NULL;
    }

    if (!code_patch_supported()) {
        FNLOG("hook_inline: %p refused, this process cannot restore execute "
              "after a code write", target);
        return NULL;
    }

    uint32_t *src = (uint32_t *)target;

    /* A 16-byte write that crosses the end of a mapped page faults, and a fault
     * inside this dylib is a dead process. */
    size_t ps = page_size_cached();
    if (((uintptr_t)target & (ps - 1)) > ps - 16) {
        FNLOG("hook_inline: %p straddles a page boundary, refused", target);
        return NULL;
    }

    for (int i = 0; i < 4; i++) {
        /* A return before the last displaced slot means the function is shorter
         * than 16 bytes; patching would overwrite the neighbouring function. */
        if (is_ret(src[i]) && i < 3) {
            FNLOG("hook_inline: %p is shorter than 16 bytes, refused", target);
            return NULL;
        }
        if (!relocatable(src[i])) {
            FNLOG("hook_inline: %p prologue insn %d (0x%08x) not relocatable",
                  target, i, src[i]);
            return NULL;
        }
    }

    FNLOG("hook_inline: installing at %p", target);

    /*
     * Trampoline placement, in the order iOS actually tolerates:
     *
     * 1. the pool inside this dylib's own __TEXT. The installer signed this
     *    image, so making one of its pages writable is the same operation the
     *    patch itself performs on the target, which the process is already
     *    allowed to do.
     * 2. anonymous memory, only when asked for. A fresh anon page made
     *    executable is unsigned executable memory; on a non-debuggable process
     *    the kernel kills it, and the kill lands inside mprotect, so nothing
     *    gets logged.
     *
     * The pool used to be the fallback, which is exactly backwards: the first
     * hook in the process went straight to the path that gets killed.
     */
    void *tramp = cave_alloc(FN_TRAMP_BYTES);
    bool anon = false;

    if (tramp) {
        if (!fn_vm_writable(tramp, FN_TRAMP_BYTES)) {
            FNLOG("hook_inline: trampoline pool not writable at %p", tramp);
            return NULL;
        }
    } else if (fn_cfg_flag("anon_tramp", 0)) {
        tramp = alloc_near((uintptr_t)target);
        if (!tramp) {
            FNLOG("hook_inline: no trampoline available for %p", target);
            return NULL;
        }
        anon = true;
        FNLOG("hook_inline: %p uses anon trampoline at %p", target, tramp);
    } else {
        FNLOG("hook_inline: trampoline pool exhausted at %p", target);
        return NULL;
    }

    uint32_t *t = (uint32_t *)tramp;
    bool ok = true;
    for (int i = 0; i < 4; i++) {
        t[i] = relocate(src[i], (uintptr_t)&src[i], (uintptr_t)&t[i], &ok);
        if (!ok) {
            FNLOG("hook_inline: relocation of %p+%d failed", target, i * 4);
            if (anon) {
                munmap(tramp, FN_HOOK_TRAMP_PAGES * 16384);
            }
            return NULL;
        }
    }
    emit_branch(&t[4], (uintptr_t)target + 16);

    if (anon) {
        if (mprotect(tramp, FN_HOOK_TRAMP_PAGES * 16384,
                     PROT_READ | PROT_EXEC) != 0) {
            FNLOG("hook_inline: mprotect trampoline failed");
            munmap(tramp, FN_HOOK_TRAMP_PAGES * 16384);
            return NULL;
        }
    } else {
        fn_make_executable(tramp, FN_TRAMP_BYTES);
    }
    sys_icache_invalidate(tramp, 64);

    fn_hook *h = calloc(1, sizeof(*h));
    if (!h) {
        if (anon) {
            munmap(tramp, FN_HOOK_TRAMP_PAGES * 16384);
        }
        return NULL;
    }
    h->target     = target;
    h->trampoline = tramp;
    h->saved_count = 4;
    memcpy(h->saved, src, 16);

    if (!fn_vm_writable(target, 16)) {
        free(h);
        return NULL;
    }
    uint32_t patch[4];
    emit_branch(patch, (uintptr_t)handler);
    memcpy(target, patch, 16);
    sys_icache_invalidate(target, 16);
    fn_make_executable(target, 16);

    if (trampoline_out) {
        *trampoline_out = tramp;
    }
    FNLOG("hook_inline: %p -> %p (tramp %p)", target, handler, tramp);
    return h;
}

void *fn_sym(const char *name)
{
    return dlsym(RTLD_DEFAULT, name);
}

void *fn_main_header(void)
{
    return (void *)_dyld_get_image_header(0);
}

uintptr_t fn_main_slide(void)
{
    return (uintptr_t)_dyld_get_image_vmaddr_slide(0);
}
