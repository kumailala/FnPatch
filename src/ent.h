#ifndef FNPATCH_ENT_H
#define FNPATCH_ENT_H

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

/* Fresh +1 dictionary holding the genuine App Store entitlements. */
CFMutableDictionaryRef fn_entitlements(void);

/* +1 value for a single entitlement key, or NULL if we do not spoof it. */
CFTypeRef fn_entitlement_value(CFStringRef key);

#endif
