#include "modules.h"
#include "hook.h"
#include "log.h"
#include "config.h"
#include "ent.h"

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stdlib.h>

/*
 * The client asks the kernel who it is (SecTask lives on top of csops) and
 * compares the answer to Epic's. We answer with Epic's.
 */

typedef CFTypeRef   (*copy_ent_t)(void *, CFStringRef, CFErrorRef *);
typedef CFTypeRef   (*copy_ents_t)(void *, CFArrayRef, CFErrorRef *);
typedef CFStringRef (*copy_sid_t)(void *, CFErrorRef *);

static copy_ent_t  g_real_copy_ent;
static copy_ents_t g_real_copy_ents;

static CFTypeRef hook_copy_ent(void *task, CFStringRef key, CFErrorRef *err)
{
    CFTypeRef spoof = fn_entitlement_value(key);
    if (spoof) {
        if (err) {
            *err = NULL;
        }
        FNLOG("entitlements: %s spoofed", "key");
        return spoof;
    }
    return g_real_copy_ent ? g_real_copy_ent(task, key, err) : NULL;
}

static CFTypeRef hook_copy_ents(void *task, CFArrayRef keys, CFErrorRef *err)
{
    CFTypeRef real = g_real_copy_ents ? g_real_copy_ents(task, keys, err) : NULL;
    CFMutableDictionaryRef merged = fn_entitlements();
    if (!merged) {
        return real;
    }
    if (real && CFGetTypeID(real) == CFDictionaryGetTypeID()) {
        CFIndex n = CFDictionaryGetCount((CFDictionaryRef)real);
        const void **ks = calloc((size_t)n, sizeof(void *));
        const void **vs = calloc((size_t)n, sizeof(void *));
        if (ks && vs) {
            CFDictionaryGetKeysAndValues((CFDictionaryRef)real, ks, vs);
            for (CFIndex i = 0; i < n; i++) {
                CFDictionarySetValue(merged, ks[i], vs[i]);
            }
        }
        free(ks);
        free(vs);
        CFRelease(real);
    }
    FNLOG("entitlements: bulk request spoofed");
    return merged;
}

static CFStringRef hook_copy_sid(void *task, CFErrorRef *err)
{
    if (err) {
        *err = NULL;
    }
    FNLOG("entitlements: signing identifier -> %s", FN_BUNDLE_ID);
    return CFStringCreateWithCString(NULL, FN_BUNDLE_ID, kCFStringEncodingUTF8);
}

void mod_entitlements_install(void)
{
    if (!fn_cfg_flag("entitlements", 1)) {
        return;
    }

    void *sym = fn_sym("SecTaskCopyValueForEntitlement");
    if (sym) {
        if (fn_hook_inline(sym, (void *)hook_copy_ent, (void **)&g_real_copy_ent)) {
            FNLOG("entitlements: SecTaskCopyValueForEntitlement hooked");
        } else {
            FNLOG("entitlements: SecTaskCopyValueForEntitlement hook failed");
        }
    } else {
        FNLOG("entitlements: SecTaskCopyValueForEntitlement absent");
    }

    sym = fn_sym("SecTaskCopyValuesForEntitlements");
    if (sym) {
        if (fn_hook_inline(sym, (void *)hook_copy_ents, (void **)&g_real_copy_ents)) {
            FNLOG("entitlements: SecTaskCopyValuesForEntitlements hooked");
        }
    } else {
        FNLOG("entitlements: SecTaskCopyValuesForEntitlements absent");
    }

    sym = fn_sym("SecTaskCopySigningIdentifier");
    if (sym) {
        void *tramp = NULL;
        if (fn_hook_inline(sym, (void *)hook_copy_sid, &tramp)) {
            FNLOG("entitlements: SecTaskCopySigningIdentifier hooked");
        }
    } else {
        FNLOG("entitlements: SecTaskCopySigningIdentifier absent");
    }
}
