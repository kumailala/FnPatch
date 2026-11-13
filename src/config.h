#ifndef FNPATCH_CONFIG_H
#define FNPATCH_CONFIG_H

#define FN_PATCH_VERSION "1.0.0"

/*
 * Values below are the genuine App Store entitlements read out of
 * Fortnite_43.10.ipa (cyan.entitlements). The client compares what the kernel
 * hands it against these; a free-dev-cert sideload differs on every field.
 */
#define FN_TEAM_ID            "JPKKQ2FLA9"
#define FN_APP_ID             "JPKKQ2FLA9.com.epicgames.FortniteGame"
#define FN_BUNDLE_ID          "com.epicgames.FortniteGame"
#define FN_APP_GROUP_1        "group.com.epicgames.FortniteGame"
#define FN_APP_GROUP_2        "group.com.epicgames.store.shared"

/* Nothing in the image list matching these is ever reported to the client. */
#define FN_HIDE_PATTERNS_INIT {                     \
    "FnPatch",        "FnMacTweak",                 \
    "CydiaSubstrate", "MobileSubstrate",            \
    "Substrate",      "libhooker",                  \
    "ellekit",        "TweakInject",                \
    "frida",          "Frida",                      \
    "/var/jb/",       "Sideload",                   \
    "AltStore",       "SideStore",                  \
    "Taurine",        "unc0ver",                    \
}

#endif
