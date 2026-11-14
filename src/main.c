#include "modules.h"
#include "log.h"
#include "config.h"
#include "hook.h"
#include "crash.h"

#include <CoreFoundation/CoreFoundation.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/*
 * The bundle identifier is not usable as a gate. Sideloadly rewrites it to a
 * random pair of words (app.passionfruit5910.lavender4318), so Epic's
 * identifier appears on exactly zero sideloaded builds and a match there is
 * never true in the only situation this dylib is used in.
 *
 * The dylib is inserted into one app by hand, so it runs unconditionally and
 * logs what it found, which is also the first line of evidence when something
 * downstream misbehaves.
 */
static void log_environment(void)
{
    CFBundleRef bundle = CFBundleGetMainBundle();
    char ident[256] = "(none)";

    if (bundle) {
        CFStringRef s = CFBundleGetIdentifier(bundle);
        if (s && !CFStringGetCString(s, ident, sizeof(ident), kCFStringEncodingUTF8)) {
            strlcpy(ident, "(unprintable)", sizeof(ident));
        }
    }

    CFStringRef exe_cf = bundle ? CFBundleGetValueForInfoDictionaryKey(bundle,
                                                                     kCFBundleExecutableKey)
                                : NULL;

    FNLOG("bundle identifier: %s", ident);
    FNLOG("matches Epic identifier: %s",
          strcasestr(ident, "fortnite") ? "yes" : "no (re-signed by the installer)");
    if (exe_cf && CFGetTypeID(exe_cf) == CFStringGetTypeID()) {
        char name[256] = "(none)";
        if (CFStringGetCString((CFStringRef)exe_cf, name, sizeof(name),
                               kCFStringEncodingUTF8)) {
            FNLOG("main executable: %s", name);
        }
    }
}

/*
 * Defaults are written once per build, not once per install.
 *
 * The old rule was "write only if the file is absent", which meant a config
 * written by an older build kept steering modules the new build had changed.
 * That is how a `hide_images=1` survived a crash fix. Now the file carries a
 * `version=` line: if it does not match this build the old file is renamed to
 * `.old`, a fresh one is written, and the in-memory cache is dropped so the
 * new values apply on this launch, not the next one.
 *
 * Only three modules exist now, and only two of them are on by default. None
 * of them patches code, because a code page on this kernel cannot be made
 * executable again once it has been written.
 */
static void write_default_config(void)
{
    const char *path = fn_cfg_path();
    char have[64] = "none";

    const char *v = fn_cfg_get("version", NULL);
    if (v) {
        snprintf(have, sizeof(have), "%s", v);
    }

    if (strcmp(have, FN_PATCH_VERSION) == 0) {
        return;
    }

    if (v) {
        char bak[640];
        snprintf(bak, sizeof(bak), "%s.old", path);
        remove(bak);
        if (rename(path, bak) == 0) {
            FNLOG("config: stale (version %s), old file kept as FnPatch.config.old", have);
        } else {
            remove(path);
            FNLOG("config: stale (version %s), replaced", have);
        }
    }

    FILE *f = fopen(path, "w");
    if (!f) {
        FNLOG("config: cannot write defaults to %s", path);
        return;
    }
    fprintf(f,
        "# FnPatch " FN_PATCH_VERSION "\n"
        "version=" FN_PATCH_VERSION "\n"
        "\n"
        "# The kick fix. A data pointer swap; no code is patched anywhere.\n"
        "uacslot=1\n"
        "# 0 = skip the signature scan and use this build's known offsets\n"
        "uacslot_scan=1\n"
        "# codes suppressed when flag==1; overrides the built-in 5,19,23,49\n"
        "# uacslot_codes=5,19,23,49\n"
        "\n"
        "# Removes our LC_LOAD_DYLIB from the in-memory Mach-O header. It writes\n"
        "# to the first page of the main executable's __TEXT, which on this kernel\n"
        "# cannot be made executable again afterwards. The page holds no code, so\n"
        "# it is safe, but it buys nothing for the kick. Off by default.\n"
        "scrub_header=0\n"
        "\n"
        "popup=1\n"
        "crash=1\n");
    fclose(f);

    fn_cfg_reload();
    FNLOG("config: wrote defaults for " FN_PATCH_VERSION);
}

__attribute__((constructor))
static void fnpatch_init(void)
{
    fn_log_init();
    fn_crash_install();
    log_environment();

    FNLOG("FnPatch %s boot, main header %p slide 0x%llx",
          FN_PATCH_VERSION, fn_main_header(),
          (unsigned long long)fn_main_slide());

    write_default_config();

    fn_step("scrub_header");
    mod_header_scrub_install();

    /*
     * The kick fix. A data pointer swap, no code patched, no trampoline, no
     * executable memory anywhere: this is the only part of the dylib that has
     * ever been confirmed working on the device.
     */
    fn_step("uacslot");
    mod_uacslot_install();

    fn_step("popup");
    mod_popup_install();

    fn_step("done");
    FNLOG("FnPatch init complete, log at Documents/FnDiag/FnPatch.log");
}

