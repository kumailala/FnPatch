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
 * Only the modules that cannot plausibly take the process down at boot are on:
 *
 *   uacslot  the kick fix, a data pointer swap, no trampoline
 *   popup    proof the dylib loaded
 *   crash    the reporter
 *   offsets  no-op unless ret0=/ret1= are set
 *
 * Everything else is off. They are all inline hooks, and inline hooks are the
 * thing that was killing the app.
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
        "# 1 = module on, 0 = module off\n"
        "uacslot=1\n"
        "uacslot_scan=1\n"
        "# uacslot_codes=5,19,23,49\n"
        "\n"
        "# Inline hooks. Off until the boot is proven clean, because every one of\n"
        "# them patches executable memory. Turn one on per launch from here.\n"
        "codesign=0\n"
        "csops=0\n"
        "entitlements=0\n"
        "fileint=0\n"
        "hide_provision=0\n"
        "eos=0\n"
        "eos_drop_server=0\n"
        "hide_images=0\n"
        "\n"
        "# Removes our LC_LOAD_DYLIB from the in-memory header. Safe but it writes\n"
        "# to the first page of the main executable's __TEXT; off by default now.\n"
        "scrub_header=0\n"
        "\n"
        "offsets=1\n"
        "popup=1\n"
        "crash=1\n"
        "\n"
        "# 1 = allow inline hooks outside the app bundle (dyld shared cache pages).\n"
        "# Those pages lose execute on restore; leave at 0.\n"
        "hook_any=0\n"
        "anon_tramp=0\n"
        "\n"
        "# Addresses relative to the main Mach-O header, comma separated.\n"
        "# ret0 / ret1 -> mov w0,#N ; ret        retvoid -> ret\n"
        "# ret1=0x123456\n"
        "# ret0=0x123456,0x654321\n");
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

    /*
     * Ask once, on our own padding page, whether this process can ever put
     * execute back on a page it made writable. The answer decides whether any
     * inline hook is allowed to run at all.
     */
    fn_step("probe");
    (void)fn_code_patch_available();

    fn_step("scrub_header");
    mod_header_scrub_install();

    /*
     * Before everything else that hooks. This module only swaps a data
     * pointer, so it cannot fail the way an executable-page trampoline does,
     * and the kick is the one symptom that hides every other one.
     */
    fn_step("uacslot");
    mod_uacslot_install();

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
