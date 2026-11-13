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

static void write_default_config(void)
{
    const char *path = fn_cfg_path();
    FILE *probe = fopen(path, "r");
    if (probe) {
        fclose(probe);
        return;
    }
    FILE *f = fopen(path, "w");
    if (!f) {
        return;
    }
    fputs(
        "# FnPatch " FN_PATCH_VERSION "\n"
        "# 1 = module on, 0 = module off\n"
        "hide_images=1\n"
        "scrub_header=1\n"
        "codesign=1\n"
        "csops=1\n"
        "entitlements=1\n"
        "fileint=1\n"
        "hide_provision=1\n"
        "eos=1\n"
        "eos_drop_server=0\n"
        "offsets=1\n"
        "popup=1\n"
        "crash=1\n"
        "\n"
        "# Addresses relative to the main Mach-O header, comma separated.\n"
        "# ret0 / ret1 -> mov w0,#N ; ret        retvoid -> ret\n"
        "# ret1=0x123456\n"
        "# ret0=0x123456,0x654321\n",
        f);
    fclose(f);
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

    fn_step("hide_images");
    mod_hide_install();

    fn_step("codesign");
    mod_codesign_install();

    fn_step("entitlements");
    mod_entitlements_install();

    fn_step("fileint");
    mod_fileint_install();

    fn_step("eos");
    mod_eos_install();

    fn_step("offsets");
    mod_offsets_install();

    fn_step("popup");
    mod_popup_install();

    fn_step("done");
    FNLOG("FnPatch init complete, log at Documents/FnDiag/FnPatch.log");
}
