#include "modules.h"
#include "hook.h"
#include "log.h"
#include "config.h"
#include "ent.h"

#include <CoreFoundation/CoreFoundation.h>
#include <dlfcn.h>

/*
 * Security/SecCode.h is macOS-only, but the symbols behind these strings are
 * present in the iOS framework, so the constants are declared locally.
 */
typedef uint32_t SecCSFlags;

#define FN_SEC_INFO_IDENTIFIER   CFSTR("identifier")
#define FN_SEC_INFO_TEAM         CFSTR("teamid")
#define FN_SEC_INFO_FLAGS        CFSTR("flags")
#define FN_SEC_INFO_ENTITLEMENTS CFSTR("entitlements-dict")

/*
 * Every signature verdict the client can consume is reduced to success here.
 * Only functions whose sole output is an OSStatus are hard-patched, so a
 * caller can never read an out-parameter we failed to fill.
 */

typedef OSStatus (*copyinfo_t)(const void *, SecCSFlags, CFDictionaryRef *);

static copyinfo_t g_real_copy_info;

static OSStatus hook_check3(const void *code, SecCSFlags flags, const void *req)
{
    FNLOG("codesign: check(%p, %u, %p) -> 0", code, (unsigned)flags, req);
    return 0;
}

static OSStatus hook_check4(const void *code, SecCSFlags flags, const void *req,
                            CFErrorRef *err)
{
    FNLOG("codesign: check_err(%p, %u, %p, %p) -> 0", code, (unsigned)flags, req, err);
    if (err) {
        *err = NULL;
    }
    return 0;
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

    if (fn_cfg_flag("patch_csops", 1)) {
        void *csops = fn_sym("csops");
        if (csops && fn_patch_ret_w0(csops, 0)) {
            FNLOG("codesign: csops -> 0");
        }
        void *csops_audit = fn_sym("csops_audittoken");
        if (csops_audit && fn_patch_ret_w0(csops_audit, 0)) {
            FNLOG("codesign: csops_audittoken -> 0");
        }
    }
}
