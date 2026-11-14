#include "modules.h"
#include "hook.h"
#include "log.h"
#include "config.h"

#include <mach/mach.h>
#include <mach-o/loader.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * UACClient message-gate, ported from the "Fn kick fix" dylib.
 *
 * The reference does not patch code. It finds one function in __TEXT, then
 * finds the single 8-byte __DATA_CONST slot that holds its address (vtable
 * entry 35 of the UACClient vtable), and swaps that pointer.
 *
 *   1. scan __TEXT for a 33-word signature, branch immediates masked
 *   2. require exactly one hit
 *   3. require exactly one slot in __DATA_CONST equal to that address
 *   4. mach_vm_protect(R|W|COPY) over the slot page, compare-exchange the 8 bytes
 *   5. restore the page's original protection
 *
 * The trampoline is an ordinary function in this dylib, so no executable
 * memory is ever allocated. The earlier boot crash was an anonymous
 * executable page made inside mprotect; nothing here needs one.
 *
 * The hooked method is bool Send(UACClient *self, int code, void *data, bool flag).
 * With flag == 1 it serialises `data`, appends a two-byte tag and a 00 0A
 * trailer, and hands the buffer to the connection at self+0x38. The reference
 * returns true before any of that for a fixed set of codes, so the caller
 * sees success while nothing is validated, queued or sent.
 *
 * This build's LC_UUID (cc0231f5-9202-3ef0-8559-7eecbbcfc27d) does not match
 * the one baked into the reference dylib, so the reference's hardcoded
 * offsets never apply here and it always takes its signature-scan path. The
 * offsets below are for this exact executable and are only a fallback.
 */

#define FN_UAC_TEXT_OFF  0x7571028ull   /* signature, __TEXT */
#define FN_UAC_SLOT_OFF  0xce5ad38ull   /* vtable entry 35, __DATA_CONST */

/* arm64, not arm64e: cpusubtype 0. Slots hold plain pointers, no ptrauth. */
#define FN_PTR_CANON(p) ((uintptr_t)(p) & 0x0000FFFFFFFFFFFFULL)

typedef struct {
    uintptr_t start;
    uintptr_t end;
} fn_range;

/*
 * The 33 words at file 0x7571028, read out of FortniteClient-IOS-Shipping.
 * Words 5, 7, 12, 15, 16, 17, 19, 20, 25, 26, 30 and 32 are bl/b: their
 * displacement is build-specific, so only the top six bits are compared.
 */
static const uint32_t k_signature[33] = {
    0xd10143ff, 0xa90257f6, 0xa9034ff4, 0xa9047bfd, 0x910103fd,
    0x96bbe7b9, 0x34000143, 0x96bbe656, 0x37000120, 0x52800013,
    0xf9400be0, 0xb4000040, 0x9642b7f3, 0xaa1303e0, 0xa9447bfd,
    0x16bbe5a8, 0x96bbe827, 0x96bbe7a7, 0x54000041, 0x96bbe6e3,
    0x96bbe886, 0x52800148, 0x39003be8, 0x12001e88, 0x79001be8,
    0x96bbe636, 0x96bbe7fb, 0xb4000080, 0x910043e1, 0x52800062,
    0x97ffd9f9, 0x52800033, 0x17ffffea,
};

static bool (*g_original)(void *, int32_t, void *, int32_t);
static uintptr_t g_slot;
static uintptr_t g_slot_had;
static bool      g_installed;

/* Codes suppressed when flag == 1. Config overrides, for tuning without a rebuild. */
#define FN_UAC_MAX_CODES 32
static int32_t g_codes[FN_UAC_MAX_CODES] = { 5, 19, 23, 49 };
static int     g_code_count = 4;

static _Atomic int g_trace_budget = 64;

static bool code_suppressed(int32_t code)
{
    for (int i = 0; i < g_code_count; i++) {
        if (g_codes[i] == code) {
            return true;
        }
    }
    return false;
}

static bool uac_send_hook(void *self, int32_t code, void *data, int32_t flag)
{
    if (flag == 1 && code_suppressed(code)) {
        return true;
    }

    if (atomic_fetch_sub_explicit(&g_trace_budget, 1, memory_order_relaxed) > 0) {
        FNLOG("uacslot: Send(code=%d flag=%d) passed through", code, flag);
    }

    return g_original(self, code, data, flag);
}

static bool segment_range(const char *want, bool file_only, fn_range *out)
{
    const struct mach_header_64 *h = fn_main_header();
    if (!h || h->magic != MH_MAGIC_64) {
        return false;
    }

    uintptr_t slide = fn_main_slide();
    const uint8_t *p = (const uint8_t *)h + sizeof(*h);

    for (uint32_t i = 0; i < h->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)p;
        if (lc->cmdsize < sizeof(*lc)) {
            return false;
        }
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *sg = (const struct segment_command_64 *)lc;
            if (strncmp(sg->segname, want, sizeof(sg->segname)) == 0) {
                uint64_t span = file_only ? sg->filesize : sg->vmsize;
                if (span < 8) {
                    return false;
                }
                out->start = slide + (uintptr_t)sg->vmaddr;
                out->end   = out->start + (uintptr_t)span;
                return true;
            }
        }
        p += lc->cmdsize;
    }
    return false;
}

/* (w & 0x7C000000) == 0x14000000 covers b and bl; anything else is exact. */
static uint32_t sig_mask(uint32_t w)
{
    return (w & 0x7C000000u) == 0x14000000u ? 0xFC000000u : 0xFFFFFFFFu;
}

static bool sig_matches(const uint32_t *p)
{
    for (int k = 0; k < 33; k++) {
        uint32_t m = sig_mask(k_signature[k]);
        if ((p[k] & m) != (k_signature[k] & m)) {
            return false;
        }
    }
    return true;
}

/*
 * Returns the address of the single match, or 0 when there is none or more
 * than one. The reference requires exactly one for the same reason: a second
 * match means the scan is no longer describing the function it was built for.
 */
static uintptr_t scan_text(const fn_range *text, int *hits_out)
{
    const uint32_t *base = (const uint32_t *)text->start;
    size_t words = (text->end - text->start) / 4;
    uintptr_t found = 0;
    int hits = 0;

    if (words < 33) {
        *hits_out = 0;
        return 0;
    }

    for (size_t i = 0; i + 33 <= words; i++) {
        if (base[i] != k_signature[0]) {
            continue;
        }
        if (!sig_matches(&base[i])) {
            continue;
        }
        hits++;
        if (!found) {
            found = (uintptr_t)&base[i];
        }
        if (hits > 1) {
            break;
        }
    }

    *hits_out = hits;
    return hits == 1 ? found : 0;
}

static int scan_slots(const fn_range *dc, uintptr_t code, uintptr_t *first)
{
    int hits = 0;
    *first = 0;

    for (uintptr_t s = dc->start; s + sizeof(uintptr_t) <= dc->end; s += sizeof(uintptr_t)) {
        uintptr_t v = FN_PTR_CANON(*(const uintptr_t *)s);
        if (v != code) {
            continue;
        }
        hits++;
        if (!*first) {
            *first = s;
        }
        if (hits > 1) {
            break;
        }
    }

    return hits;
}

/*
 * VM_PROT_COPY forces a private dirty page, which __DATA_CONST requires: the
 * segment is mapped read-only and clean, so a plain write protect is refused
 * on some kernels and silently shared on others.
 */
static bool slot_write(uintptr_t slot, uintptr_t expect, uintptr_t value)
{
    vm_size_t ps = (vm_size_t)getpagesize();
    uintptr_t page = slot & ~(uintptr_t)(ps - 1);

    mach_vm_address_t region = slot;
    mach_vm_size_t    region_size = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object = MACH_PORT_NULL;

    kern_return_t kr = mach_vm_region(mach_task_self(), &region, &region_size,
                                      VM_REGION_BASIC_INFO_64,
                                      (vm_region_info_t)&info, &count, &object);
    if (kr != KERN_SUCCESS) {
        FNLOG("uacslot: mach_vm_region failed at 0x%lx (0x%x)", (unsigned long)slot, kr);
        return false;
    }
    vm_prot_t original = info.protection;

    kr = mach_vm_protect(mach_task_self(), page, ps, false,
                         VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr != KERN_SUCCESS) {
        FNLOG("uacslot: mach_vm_protect(RW) failed at 0x%lx (0x%x)", (unsigned long)page, kr);
        return false;
    }

    uintptr_t *cell = (uintptr_t *)slot;
    bool swapped = __atomic_compare_exchange_n(cell, &expect, value, false,
                                               __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);

    kr = mach_vm_protect(mach_task_self(), page, ps, false, original);
    if (kr != KERN_SUCCESS) {
        FNLOG("uacslot: restoring protection 0x%x failed at 0x%lx (0x%x)",
              (unsigned)original, (unsigned long)page, kr);
    }

    if (!swapped) {
        FNLOG("uacslot: compare-exchange lost, slot now 0x%lx",
              (unsigned long)*cell);
    }
    return swapped;
}

static void parse_codes(void)
{
    const char *raw = fn_cfg_get("uacslot_codes", NULL);
    if (!raw) {
        return;
    }

    char buf[256];
    snprintf(buf, sizeof(buf), "%s", raw);

    int n = 0;
    char *save = NULL;
    for (char *tok = strtok_r(buf, ",; ", &save); tok && n < FN_UAC_MAX_CODES;
         tok = strtok_r(NULL, ",; ", &save)) {
        char *end = NULL;
        long v = strtol(tok, &end, 0);
        if (end == tok) {
            FNLOG("uacslot: codes entry '%s' is not a number, skipped", tok);
            continue;
        }
        g_codes[n++] = (int32_t)v;
    }

    if (n > 0) {
        g_code_count = n;
        char joined[192] = "";
        for (int i = 0; i < n; i++) {
            char one[16];
            snprintf(one, sizeof(one), i ? ",%d" : "%d", g_codes[i]);
            strncat(joined, one, sizeof(joined) - strlen(joined) - 1);
        }
        FNLOG("uacslot: suppressing codes {%s} with flag==1", joined);
    }
}

void mod_uacslot_install(void)
{
    if (!fn_cfg_flag("uacslot", 1)) {
        FNLOG("uacslot: disabled by config");
        return;
    }

    fn_range text = { 0, 0 };
    fn_range dc = { 0, 0 };

    if (!segment_range("__TEXT", true, &text)) {
        FNLOG("uacslot: __TEXT not found in the main image, giving up");
        return;
    }
    if (!segment_range("__DATA_CONST", false, &dc)) {
        FNLOG("uacslot: __DATA_CONST not found in the main image, giving up");
        return;
    }

    uintptr_t slide = fn_main_slide();
    FNLOG("uacslot: __TEXT 0x%lx-0x%lx __DATA_CONST 0x%lx-0x%lx",
          (unsigned long)text.start, (unsigned long)text.end,
          (unsigned long)dc.start, (unsigned long)dc.end);

    uintptr_t code = 0;
    uintptr_t slot = 0;

    if (fn_cfg_flag("uacslot_scan", 1)) {
        int text_hits = 0;
        code = scan_text(&text, &text_hits);
        FNLOG("uacslot: signature matches in __TEXT: %d", text_hits);

        if (code) {
            int slot_hits = scan_slots(&dc, code, &slot);
            FNLOG("uacslot: slots holding 0x%lx: %d", (unsigned long)code, slot_hits);
        }
    } else {
        FNLOG("uacslot: scan disabled by config, using known offsets");
    }

    if (!code) {
        code = slide + (uintptr_t)FN_UAC_TEXT_OFF;
        if (code < text.start || code + 4 * 33 > text.end) {
            FNLOG("uacslot: fallback function 0x%lx is outside __TEXT, giving up",
                  (unsigned long)code);
            return;
        }
        if (!sig_matches((const uint32_t *)code)) {
            FNLOG("uacslot: fallback function 0x%lx does not match the signature, giving up",
                  (unsigned long)code);
            return;
        }
        FNLOG("uacslot: using fallback function 0x%lx", (unsigned long)code);
    }

    if (!slot) {
        slot = slide + (uintptr_t)FN_UAC_SLOT_OFF;
        if (slot < dc.start || slot >= dc.end) {
            FNLOG("uacslot: fallback slot 0x%lx is outside __DATA_CONST, giving up",
                  (unsigned long)slot);
            return;
        }
        if (FN_PTR_CANON(*(const uintptr_t *)slot) != code) {
            FNLOG("uacslot: fallback slot 0x%lx holds 0x%lx, expected 0x%lx, giving up",
                  (unsigned long)slot,
                  (unsigned long)FN_PTR_CANON(*(const uintptr_t *)slot),
                  (unsigned long)code);
            return;
        }
        FNLOG("uacslot: using fallback slot 0x%lx (vtable 0x%lx, entry %d)",
              (unsigned long)slot, (unsigned long)(slot - 0x118), 35);
    }

    if (slot < dc.start || slot >= dc.end) {
        FNLOG("uacslot: slot 0x%lx is outside __DATA_CONST, giving up", (unsigned long)slot);
        return;
    }

    parse_codes();

    g_slot     = slot;
    g_slot_had = *(const uintptr_t *)slot;
    g_original = (bool (*)(void *, int32_t, void *, int32_t))g_slot_had;

    FNLOG("uacslot: slot 0x%lx holds 0x%lx, hook %p",
          (unsigned long)slot, (unsigned long)g_slot_had, (void *)uac_send_hook);

    if (!slot_write(slot, g_slot_had, (uintptr_t)uac_send_hook)) {
        g_original = NULL;
        FNLOG("uacslot: install failed");
        return;
    }

    g_installed = true;
    FNLOG("uacslot: slot 0x%lx now 0x%lx (was 0x%lx)",
          (unsigned long)slot,
          (unsigned long)*(const uintptr_t *)slot,
          (unsigned long)g_slot_had);
}

/*
 * Put the pointer back before this image goes away. A dylib that unloads with
 * a vtable slot aimed at its own __TEXT leaves the next virtual call branching
 * into an unmapped page, which is a crash with no useful backtrace.
 */
__attribute__((destructor))
static void mod_uacslot_uninstall(void)
{
    if (!g_installed || !g_slot) {
        return;
    }
    g_installed = false;

    uintptr_t current = *(const uintptr_t *)g_slot;
    if (FN_PTR_CANON(current) == (uintptr_t)uac_send_hook) {
        if (slot_write(g_slot, current, g_slot_had)) {
            FNLOG("uacslot: slot 0x%lx restored to 0x%lx",
                  (unsigned long)g_slot, (unsigned long)g_slot_had);
        }
    }
    g_original = NULL;
}
