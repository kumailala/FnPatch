#include "modules.h"
#include "log.h"
#include "config.h"
#include "hook.h"

#include <CoreFoundation/CoreFoundation.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

static bool is_target_app(void)
{
    CFBundleRef bundle = CFBundleGetMainBundle();
    if (!bundle) {
        return false;
    }
    CFStringRef ident = CFBundleGetIdentifier(bundle);
    if (!ident) {
        return false;
    }
    char buf[256];
    if (!CFStringGetCString(ident, buf, sizeof(buf), kCFStringEncodingUTF8)) {
        return false;
    }
    FNLOG("bundle identifier: %s", buf);
    if (strcmp(buf, FN_BUNDLE_ID) == 0) {
        return true;
    }
    /*
     * Sideloadly, AltStore and friends rewrite the identifier to fit the
     * signing profile (com.<team>.FortniteGame, com.example.abc123.FortniteGame
     * and similar), so the exact match above is not the common case on a
     * sideload. Anything still calling itself Fortnite is the app we shipped in.
     */
    return strcasestr(buf, "fortnite") != NULL;
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
        "codesign=1\n"
        "patch_csops=0\n"
        "entitlements=1\n"
        "fileint=1\n"
        "eos=1\n"
        "eos_drop_server=0\n"
        "offsets=1\n"
        "popup=1\n"
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

    if (!is_target_app()) {
        FNLOG("not the target app, FnPatch inactive");
        return;
    }

    FNLOG("FnPatch %s boot, main header %p slide 0x%llx",
          FN_PATCH_VERSION, fn_main_header(),
          (unsigned long long)fn_main_slide());

    write_default_config();

    mod_hide_install();
    mod_codesign_install();
    mod_entitlements_install();
    mod_fileint_install();
    mod_eos_install();
    mod_offsets_install();
    mod_popup_install();

    FNLOG("FnPatch init complete, log at $HOME/Documents/FnPatch.log");
}
