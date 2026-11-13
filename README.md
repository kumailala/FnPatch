# FnPatch

In-memory bypass for sideloaded Fortnite iOS 43.10, aimed at

> You were removed from the match due to errors in your installation.
> Please verify or reinstall Fortnite to correct these issues.

Nothing in this repo is a patched IPA. It is a dylib that changes what the
client sees about itself while it runs.

## What the two stock IPAs told us

```
normal  : 213 files
tweaked : 216 files  (+Frameworks/FnMacTweak.dylib 818368
                      +Frameworks/CydiaSubstrate.framework/*)
          -Frameworks/FnMacCrashFix.dylib 132752
main binary: identical size 321511696, different bytes -> load command patch only
```

So the difference between a build that gets kicked and one that does not is not
the binary's code. It is what the binary admits about itself, and the tweaked
IPA did it with a substrate tweak plus a swapped crash dylib. Ours does it with
one dylib and no substrate.

There is no EAC framework in the bundle. The stack is:

- `EOSSDK.framework` — Epic Online Services, including the client anti-cheat interface
- `Security.framework` — signature and entitlement verdicts
- `libdyld` — the loaded-image list the client can enumerate

## Modules

| module | target | effect |
|---|---|---|
| `mod_hide` | `_dyld_image_count` / `_dyld_get_image_name` / `_dyld_get_image_header` | the list is filtered live and indices are remapped, so an index from `count()` is always valid for `name()`/`header()`; FnPatch, Substrate, frida and friends are not there |
| `mod_codesign` | `SecStaticCodeCheckValidity`, `SecCodeCheckValidity`, `…WithErrors`, `MISValidateSignature`, `SecCodeCopySigningInformation`, `csops`, `csops_audittoken` | every signature verdict is success; signing info reports Epic's team. `csops` patching is off by default — it returns an OSStatus without filling the caller's status buffer, so it is opt-in via `patch_csops=1` |
| `mod_entitlements` | `SecTaskCopyValueForEntitlement`, `SecTaskCopyValuesForEntitlements`, `SecTaskCopySigningIdentifier` | the kernel-side identity reads back as `JPKKQ2FLA9` / `com.epicgames.FortniteGame` |
| `mod_fileint` | `open`, `openat`, `stat`, `lstat`, `access`, `fopen` | nothing can open or stat the dylib; every integrity-looking path is logged |
| `mod_eos` | `EOS_AntiCheatClient_PollStatus`, `BeginSession`, `ReceiveMessageFromServer` | violations are forced to `EOS_ACCVT_NoViolation` and the session call returns `EOS_Success`. Server messages pass through untouched unless `eos_drop_server=1`, because starving the handshake invites a different kick |
| `mod_offsets` | config-driven | `ret0` / `ret1` / `retvoid` address lists for whatever the log points at |

Genuine values, read out of `Fortnite_43.10.ipa/…/cyan.entitlements`:

```
team    JPKKQ2FLA9
app id  JPKKQ2FLA9.com.epicgames.FortniteGame
bundle  com.epicgames.FortniteGame
groups  group.com.epicgames.FortniteGame
        group.com.epicgames.store.shared
```

## Build

No Mac needed — push and let CI build it:

```
.github/workflows/build.yml   ->  macos-latest, artifact "FnPatch-dylib"
```

On a Mac with Xcode:

```sh
./build.sh            # -> FnPatch.dylib
```

## Inject

```sh
python tools/inject.py --ipa Fortnite_43.10.ipa --dylib FnPatch.dylib \
                       --out Fortnite_FnPatch.ipa
```

It copies the dylib to `Frameworks/`, then inserts into the main Mach-O:

```
LC_LOAD_DYLIB  @rpath/FnPatch.dylib
LC_RPATH       @executable_path/Frameworks
```

Then sign the result with Sideloadly / AltStore / SideStore. Do not pre-sign
with a different identity.

## Read the result

The dylib writes `Documents/FnPatch.log` inside the app container:

```
FnPatch 1.0.0 boot, main header 0x102a40000 slide 0x0
hook_inline: 0x1b2c3d000 -> 0x1b1f04000 (tramp 0x1b2c30000)
hide: 0x1a0b4c000/Substrate/libsubstrate.dylib
fs: stat(/var/containers/…/cookeddata/…/Manifest.upl)
codesign: check(0x0, 2, 0x0) -> 0
```

If the kick still lands, `fs:` lines immediately before it name the file the
client was inspecting, and the caller is the function to neutralise:

```
ret1=0x<offset>
```

in `Documents/FnPatch.config` (offsets are relative to the Mach-O header).

## Config

`Documents/FnPatch.config`, written on first launch:

```
hide_images=1
codesign=1
patch_csops=0
entitlements=1
fileint=1
eos=1
eos_drop_server=0
offsets=1
ret0=0x123456
ret1=0x123456
retvoid=0x123456
```

## Honest notes

- The inline hook displaces four instructions. A prologue whose first 16 bytes
  contain a direct `B`/`BL` is refused and logged rather than miscompiled —
  that is the only case where a module silently does less than advertised.
- `mod_hide` resolves the three dyld functions through `dlsym`, not through this
  dylib's own import stubs, so the hooks land on the function the client calls.
  The list is filtered on every call, so images loaded after boot are still
  counted and indexed correctly.
- iOS 15+ shipped binaries may use chained fixups; this design sidesteps that
  entirely by patching code, not the symbol pointers.
- The EOS anti-cheat client only exists once `EOSSDK` is loaded, so that module
  waits on a watchdog for up to 60 s.
