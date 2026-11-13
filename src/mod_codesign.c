#include "modules.h"
#include "hook.h"
#include "log.h"
#include "config.h"
#include "ent.h"

#include <CoreFoundation/CoreFoundation.h>
#include <dlfcn.h>
#include <string.h>

/*
 * Security/SecCode.h is macOS-only, but the symbols behind these strings are
 * present in the iOS framework, so the constants are declared locally.
 */
typedef uint32_t SecCSFlags;

#ifndef __MACTYPES__
typedef int32_t OSStatus;
#endif

#define FN_SEC_INFO_IDENTIFIER   CFSTR("identifier")
#define FN_SEC_INFO_TEAM         CFSTR("teamid")
#define FN_SEC_INFO_FLAGS        CFSTR("flags")
#define FN_SEC_INFO_ENTITLEMENTS CFSTR("entitlements-dict")
#define FN_SEC_INFO_UNIQUE       CFSTR("unique")
#define FN_SEC_INFO_CDHASHES     CFSTR("cdhashes")

/* Opaque signature verdicts are reduced to success; anything with an
 * out-parameter is answered rather than patched, so no caller reads a buffer
 * we failed to fill. */

typedef OSStatus (*copyinfo_t)(const void *, SecCSFlags, CFDictionaryRef *);
typedef int (*csops_t)(int, unsigned int, void *, size_t);

static copyinfo_t g_real_copy_info;
static csops_t    g_real_csops;

/*
 * bsd/sys/codesign.h. Only the two operations the client can draw a verdict
 * from are handled; everything else falls through to the kernel.
 */
#define FN_CS_OPS_STATUS 0
#define FN_CS_OPS_CDHASH 5

#define FN_CS_VALID          0x00000001u
#define FN_CS_GET_TASK_ALLOW 0x00000004u
#define FN_CS_DEBUGGED       0x10000000u

static const uint8_t g_cdharsh_bytes[20] = { FN_CDHASH_BYTES };

static OSStatus hook_check3(const void *code, SecCSFlags flags, const void *req)
{
    FNLOG("codesign: check(%p, %u, %p) -> 0 caller=+0x%llx", code, (unsigned)flags, req,
          (unsigned long long)((uintptr_t)__builtin_return_address(0) -
                               (uintptr_t)fn_main_header()));
    return 0;
}

static OSStatus hook_check4(const void *code, SecCSFlags flags, const void *req,
                            CFErrorRef *err)
{
    FNLOG("codesign: check_err(%p, %u, %p, %p) -> 0 caller=+0x%llx", code,
          (unsigned)flags, req, err,
          (unsigned long long)((uintptr_t)__builtin_return_address(0) -
                               (uintptr_t)fn_main_header()));
    if (err) {
        *err = NULL;
    }
    return 0;
}

static CFTypeRef cdhash_data(void)
{
    return CFDataCreate(NULL, g_cdharsh_bytes, (CFIndex)sizeof(g_cdharsh_bytes));
}

static OSStatus hook_copy_info(const void *code, SecCSFlags flags, CFDictionaryRef *info)
{
    OSStatus st = g_real_copy_info ? g_real_copy_info(code, flags, info) : 0;

    if (info) {
        CFMutableDictionaryRef m = NULL;
        if (*info) {
            m = CFDictionaryCreateMutableCopy(NULL, 0, *info);
            CFRelease(*info);
        } else {
            m = CFDictionaryCreateMutable(NULL, 0,
                &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        }
        if (m) {
            CFMutableDictionaryRef ent = fn_entitlements();
            CFStringRef ident = CFStringCreateWithCString(NULL, FN_BUNDLE_ID,
                                                          kCFStringEncodingUTF8);
            CFStringRef team = CFStringCreateWithCString(NULL, FN_TEAM_ID,
                                                         kCFStringEncodingUTF8);
            int32_t zero = 0;
            CFNumberRef flags_num = CFNumberCreate(NULL, kCFNumberSInt32Type, &zero);

            CFTypeRef cd = cdhash_data();
            if (cd) {
                CFDictionarySetValue(m, FN_SEC_INFO_UNIQUE, cd);
                const void *items[1] = { cd };
                CFArrayRef arr = CFArrayCreate(NULL, items, 1, &kCFTypeArrayCallBacks);
                if (arr) {
                    CFDictionarySetValue(m, FN_SEC_INFO_CDHASHES, arr);
                    CFRelease(arr);
                }
                CFRelease(cd);
            }
            CFDictionarySetValue(m, FN_SEC_INFO_IDENTIFIER, ident);
            CFDictionarySetValue(m, FN_SEC_INFO_TEAM, team);
            CFDictionarySetValue(m, FN_SEC_INFO_FLAGS, flags_num);
            if (ent) {
                CFDictionarySetValue(m, FN_SEC_INFO_ENTITLEMENTS, ent);
                CFRelease(ent);
            }
            CFRelease(ident);
            CFRelease(team);
            CFRelease(flags_num);
            *info = m;
        }
        st = 0;
    }
    FNLOG("codesign: copy_signing_information -> %d", (int)st);
    return st;
}

/*
 * A sideloaded build carries CS_GET_TASK_ALLOW and CS_DEBUGGED; a store build
 * carries neither. The status word is sanitised rather than faked, and the
 * CDHash is the same value SecCodeCopySigningInformation reports, so the two
 * answers never contradict each other.
 */
static int hook_csops(int pid, unsigned int ops, void *addr, size_t size)
{
    if (ops == FN_CS_OPS_STATUS && addr && size >= sizeof(uint32_t)) {
        int rc = g_real_csops ? g_real_csops(pid, ops, addr, size) : -1;
        if (rc == 0) {
            uint32_t flags = *(uint32_t *)addr;
            uint32_t clean = (flags & ~(FN_CS_GET_TASK_ALLOW | FN_CS_DEBUGGED)) | FN_CS_VALID;
            if (clean != flags) {
                FNLOG("codesign: csops status 0x%08x -> 0x%08x", flags, clean);
                *(uint32_t *)addr = clean;
            }
        }
        return rc;
    }
    if (ops == FN_CS_OPS_CDHASH && addr && size >= sizeof(g_cdharsh_bytes)) {
        memcpy(addr, g_cdharsh_bytes, sizeof(g_cdharsh_bytes));
        return 0;
    }
    return g_real_csops ? g_real_csops(pid, ops, addr, size) : -1;
}

void mod_codesign_install(void)
{
    if (!fn_cfg_flag("codesign", 1)) {
        return;
    }

    static const char *const check3_names[] = {
        "SecStaticCodeCheckValidity",
        "SecCodeCheckValidity",
        "MISValidateSignature",
    };
    static const char *const check4_names[] = {
        "SecStaticCodeCheckValidityWithErrors",
        "SecCodeCheckValidityWithErrors",
    };

    void *tramp = NULL;

    for (size_t i = 0; i < sizeof(check3_names) / sizeof(check3_names[0]); i++) {
        void *sym = fn_sym(check3_names[i]);
        if (!sym) {
            FNLOG("codesign: %s absent", check3_names[i]);
            continue;
        }
        if (!fn_hook_inline(sym, (void *)hook_check3, &tramp)) {
            FNLOG("codesign: %s hook failed", check3_names[i]);
        }
    }
    for (size_t i = 0; i < sizeof(check4_names) / sizeof(check4_names[0]); i++) {
        void *sym = fn_sym(check4_names[i]);
        if (!sym) {
            FNLOG("codesign: %s absent", check4_names[i]);
            continue;
        }
        if (!fn_hook_inline(sym, (void *)hook_check4, &tramp)) {
            FNLOG("codesign: %s hook failed", check4_names[i]);
        }
    }

    void *info = fn_sym("SecCodeCopySigningInformation");
    if (info) {
        if (fn_hook_inline(info, (void *)hook_copy_info, (void **)&g_real_copy_info)) {
            FNLOG("codesign: SecCodeCopySigningInformation hooked");
        } else {
            FNLOG("codesign: SecCodeCopySigningInformation hook failed");
        }
    } else {
        FNLOG("codesign: SecCodeCopySigningInformation absent");
    }

    if (fn_cfg_flag("csops", 1)) {
        void *csops = fn_sym("csops");
        if (csops && fn_hook_inline(csops, (void *)hook_csops, (void **)&g_real_csops)) {
            FNLOG("codesign: csops hooked");
        } else {
            FNLOG("codesign: csops hook failed");
        }
    }
}
