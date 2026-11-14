#ifndef FNPATCH_CONFIG_H
#define FNPATCH_CONFIG_H

#define FN_PATCH_VERSION "1.1.0"

/*
 * Nothing else lives here on purpose.
 *
 * The entitlement and CDHash spoofing values that used to sit in this file fed
 * mod_entitlements.c and mod_codesign.c, which hooked the SecTask, SecCode,
 * MISValidateSignature and csops symbols. Those live in the dyld shared cache,
 * an inline hook on them cannot restore execute on this kernel, and they were
 * the first thing to take the process down. They are deleted, so the values
 * they wanted are gone with them.
 *
 * The kick fix does not need them: mod_uacslot.c cuts the report at the exit
 * instead of trying to make a sideloaded signature look like Epic's.
 */

#endif
