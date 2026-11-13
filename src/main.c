#include "modules.h"
#include "log.h"
#include "config.h"
#include "hook.h"

#include <CoreFoundation/CoreFoundation.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
    return strcmp(buf, FN_BUNDLE_ID) == 0;
}

static void write_default_config(void)
{
    const char *home = getenv("HOME");
    if (!home) {
        return;
    }
    char path[512];
    snprintf(path, sizeof(path), "%s/Documents/FnPatch.config", home);
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
        "offsets=1\n"
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
    if (!is_target_app()) {
        return;
    }

    fn_log_init();
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

    FNLOG("FnPatch init complete, log at $HOME/Documents/FnPatch.log");
}
