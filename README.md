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
| `mod_uacslot` | `UACClient::Send`, vtable entry 35 in `__DATA_CONST` | the message gate: for codes `{5,19,23,49}` sent with `flag==1` it returns true without serialising, queueing or sending. Everything else tail-calls the original. This is the module aimed at the kick |
| `mod_hide` | `_dyld_image_count` / `_dyld_get_image_name` / `_dyld_get_image_header` | the list is filtered live and indices are remapped, so an index from `count()` is always valid for `name()`/`header()`; FnPatch, Substrate, frida and friends are not there. Off by default |
| `mod_codesign` | `SecStaticCodeCheckValidity`, `SecCodeCheckValidity`, `…WithErrors`, `MISValidateSignature`, `SecCodeCopySigningInformation`, `csops`, `csops_audittoken` | every signature verdict is success; signing info reports Epic's team. `csops` patching is off by default — it returns an OSStatus without filling the caller's status buffer, so it is opt-in via `patch_csops=1` |
| `mod_entitlements` | `SecTaskCopyValueForEntitlement`, `SecTaskCopyValuesForEntitlements`, `SecTaskCopySigningIdentifier` | the kernel-side identity reads back as `JPKKQ2FLA9` / `com.epicgames.FortniteGame` |
| `mod_fileint` | `open`, `openat`, `stat`, `lstat`, `access`, `fopen` | nothing can open or stat the dylib; every integrity-looking path is logged |
| `mod_eos` | `EOS_AntiCheatClient_PollStatus`, `BeginSession`, `ReceiveMessageFromServer` | violations are forced to `EOS_ACCVT_NoViolation` and the session call returns `EOS_Success`. Server messages pass through untouched unless `eos_drop_server=1`, because starving the handshake invites a different kick |
| `mod_offsets` | config-driven | `ret0` / `ret1` / `retvoid` address lists for whatever the log points at |
| `mod_popup` | config-driven (`popup=1`) | one-shot "dylib loaded OK" alert at launch, retried on the main queue until the game has a view controller to present on |

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

The dylib writes `Documents/FnDiag/FnPatch.log` inside the app container, which
is the folder the Files app shows for this bundle:

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

in `Documents/FnDiag/FnPatch.config` (offsets are relative to the Mach-O header).

## Config

`Documents/FnDiag/FnPatch.config`, written on first launch:

```
uacslot=1
uacslot_scan=1
hide_images=0
scrub_header=1
codesign=1
csops=1
entitlements=1
fileint=1
hide_provision=1
eos=1
eos_drop_server=0
offsets=1
popup=1
crash=1
anon_tramp=0
ret0=0x123456
ret1=0x123456
retvoid=0x123456
```

- `crash` arms a fatal-signal reporter: on SIGSEGV/SIGBUS/SIGILL it appends
  `crash: <signal> pc=0x… lr=0x… addr=0x… step=<what was running>` to the log
  before re-raising, so a dead process still leaves its last line of evidence.
- `anon_tramp` allows the inline hooker to fall back to an anonymous
  trampoline page when the in-image pool is exhausted. It is off by default:
  unsigned executable memory is killed by the kernel inside `mprotect`, which
  is exactly how a silent boot-time death happens.

- `scrub_header` removes the injected `LC_LOAD_DYLIB` from the in-memory Mach-O
  header, so a load-command walk sees the stock layout. The file on disk is
  untouched.
- `csops` hooks `csops(2)` and rewrites `CS_OPS_STATUS` (drops `CS_DEBUGGED` and
  `CS_GET_TASK_ALLOW`, adds `CS_VALID`) and `CS_OPS_CDHASH` (answers with the
  stock IPA's CDHash), so kernel-level queries agree with the userspace answer.
- `hide_provision` denies `embedded.mobileprovision`. A store build has none, a
  sideload does, and nothing in the game reads it at runtime.

## Honest notes

- The inline hook displaces four instructions. A prologue whose first 16 bytes
  contain a direct `B`/`BL` is refused and logged rather than miscompiled —
  that is the only case where a module silently does less than advertised.
- `mod_hide` resolves the three dyld functions through `dlsym`, not through this
  dylib's own import stubs, so the hooks land on the function the client calls.
  The list is filtered on every call, so images loaded after boot are still
  counted and indexed correctly.
- iOS 15+ shipped binaries may use chained fixups. `mod_uacslot` sidesteps
  the encoding entirely by scanning the loaded image at runtime, after dyld
  has already rebound every pointer: the `__DATA_CONST` slot holds a plain
  address there, not the packed `0x0010000007571028` form stored in the file.
- `mod_uacslot` never allocates executable memory. It writes one 8-byte
  pointer into an existing `__DATA_CONST` page under `VM_PROT_COPY`, and its
  trampoline is an ordinary function in this dylib's own `__TEXT`.

## The kick fix, as recovered

The reference `Fn kick fix.dylib` does not patch code. It scans `__TEXT` for a
33-word signature with branch immediates masked, requires exactly one match,
requires exactly one 8-byte `__DATA_CONST` slot equal to that address, then
`mach_vm_protect`s the page and compare-exchanges the pointer.

For this build:

```
signature   0xd10143ff a90257f6 a9034ff4 a9047bfd 910103fd …   (33 words)
matches     1   at vaddr 0x107571028  (file 0x7571028)
slots       1   at vaddr 0x10ce5ad38  (vtable 0x10ce5ac20, entry 35)
class       UACClient  (name string at 0x10be7ba6e)
method      bool Send(UACClient *self, int code, void *data, bool flag)
```

The reference also hardcodes two offsets (`0x74c1334`, `0xcd32e18`) and an
LC_UUID (`e40351ab-50a4-3f3e-b32b-a07a311d9b73`). This executable's UUID is
`cc0231f5-9202-3ef0-8559-7eecbbcfc27d`, so its fast path never applies and the
scan is the live route. FnPatch keeps the same two numbers as a fallback,
guarded by a signature check before it is used.
- The EOS anti-cheat client only exists once `EOSSDK` is loaded, so that module
  waits on a watchdog for up to 60 s.
