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

bool fn_vm_writable(void *addr, size_t len)
{
    vm_size_t ps = 0;
    host_page_size(mach_host_self(), &ps);
    if (!ps) {
        ps = 16384;
    }
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

/* Restore execute-only protection after patching, so the page does not stay writable. */
static void fn_vm_executable(void *addr, size_t len)
{
    vm_size_t ps = 0;
    host_page_size(mach_host_self(), &ps);
    if (!ps) {
        ps = 16384;
    }
    uintptr_t page = (uintptr_t)addr & ~(uintptr_t)(ps - 1);
    size_t    off  = (uintptr_t)addr - page;
    size_t    size = ((off + len + ps - 1) / ps) * ps;
    vm_protect(mach_task_self(), page, size, false, VM_PROT_READ | VM_PROT_EXECUTE);
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
    fn_vm_executable(target, sizeof(insn));
    return true;
}

bool fn_patch_ret_void(void *target)
{
    if (!target) {
        return false;
    }
    uint32_t insn = A64_RET;
    if (!fn_vm_writable(target, sizeof(insn))) {
        return false;
    }
    memcpy(target, &insn, sizeof(insn));
    sys_icache_invalidate(target, sizeof(insn));
    fn_vm_executable(target, sizeof(insn));
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

fn_hook *fn_hook_inline(void *target, void *handler, void **trampoline_out)
{
    if (!target || !handler) {
        return NULL;
    }

    uint32_t *src = (uint32_t *)target;
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

    void *tramp = alloc_near((uintptr_t)target);
    if (!tramp) {
        return NULL;
    }

    uint32_t *t = (uint32_t *)tramp;
    bool ok = true;
    for (int i = 0; i < 4; i++) {
        t[i] = relocate(src[i], (uintptr_t)&src[i], (uintptr_t)&t[i], &ok);
        if (!ok) {
            FNLOG("hook_inline: relocation of %p+%d failed", target, i * 4);
            munmap(tramp, FN_HOOK_TRAMP_PAGES * 16384);
            return NULL;
        }
    }
    emit_branch(&t[4], (uintptr_t)target + 16);

    if (mprotect(tramp, FN_HOOK_TRAMP_PAGES * 16384,
                 PROT_READ | PROT_EXEC) != 0) {
        FNLOG("hook_inline: mprotect trampoline failed");
        munmap(tramp, FN_HOOK_TRAMP_PAGES * 16384);
        return NULL;
    }
    sys_icache_invalidate(tramp, 64);

    fn_hook *h = calloc(1, sizeof(*h));
    if (!h) {
        munmap(tramp, FN_HOOK_TRAMP_PAGES * 16384);
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
    fn_vm_executable(target, 16);

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
