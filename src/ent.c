#include "ent.h"
#include "config.h"

static CFStringRef make(const char *s)
{
    return CFStringCreateWithCString(NULL, s, kCFStringEncodingUTF8);
}

CFMutableDictionaryRef fn_entitlements(void)
{
    CFMutableDictionaryRef d = CFDictionaryCreateMutable(NULL, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    if (!d) {
        return NULL;
    }

    CFStringRef team    = make(FN_TEAM_ID);
    CFStringRef appid   = make(FN_APP_ID);
    CFStringRef aps     = make("production");
    CFStringRef devchk  = make("production");
    CFStringRef doms[2] = { make("applinks:www.fortnite.com"),
                            make("applinks:play.fn.gg") };
    CFStringRef grps[2] = { make(FN_APP_GROUP_1), make(FN_APP_GROUP_2) };
    CFArrayRef  dom_arr = CFArrayCreate(NULL, (const void **)doms, 2,
                                        &kCFTypeArrayCallBacks);
    CFArrayRef  grp_arr = CFArrayCreate(NULL, (const void **)grps, 2,
                                        &kCFTypeArrayCallBacks);

    CFDictionarySetValue(d, CFSTR("com.apple.developer.team-identifier"), team);
    CFDictionarySetValue(d, CFSTR("application-identifier"), appid);
    CFDictionarySetValue(d, CFSTR("com.apple.developer.kernel.increased-memory-limit"),
                         kCFBooleanTrue);
    CFDictionarySetValue(d, CFSTR("com.apple.developer.kernel.extended-virtual-addressing"),
                         kCFBooleanTrue);
    CFDictionarySetValue(d, CFSTR("aps-environment"), aps);
    CFDictionarySetValue(d, CFSTR("com.apple.developer.devicecheck.appattest-environment"),
                         devchk);
    CFDictionarySetValue(d, CFSTR("com.apple.developer.associated-domains"), dom_arr);
    CFDictionarySetValue(d, CFSTR("com.apple.security.application-groups"), grp_arr);
    CFDictionarySetValue(d, CFSTR("get-task-allow"), kCFBooleanFalse);
    CFDictionarySetValue(d, CFSTR("beta-reports-active"), kCFBooleanTrue);

    CFRelease(team);
    CFRelease(appid);
    CFRelease(aps);
    CFRelease(devchk);
    CFRelease(doms[0]);
    CFRelease(doms[1]);
    CFRelease(grps[0]);
    CFRelease(grps[1]);
    CFRelease(dom_arr);
    CFRelease(grp_arr);
    return d;
}

CFTypeRef fn_entitlement_value(CFStringRef key)
{
    if (!key) {
        return NULL;
    }
    CFMutableDictionaryRef d = fn_entitlements();
    if (!d) {
        return NULL;
    }
    CFTypeRef v = CFDictionaryGetValue(d, key);
    if (v) {
        CFRetain(v);
    }
    CFRelease(d);
    return v;
}
