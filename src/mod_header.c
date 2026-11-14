#include "modules.h"
#include "hook.h"
#include "log.h"
#include "config.h"

#include <mach-o/loader.h>
#include <string.h>

// Hiding the dylib from the loaded-image list is not enough on its own: the
// injected LC_LOAD_DYLIB is still sitting in the main executable's Mach-O
// header, and anything that walks the load commands (including a check that
// never touches dyld) can read it straight out of memory.
//
// dyld has already mapped and bound us by the time this runs, so the command
// can be deleted from the in-memory header. Everything after it is moved down
// and the tail is zeroed, which leaves the header byte-identical to the stock
// Mach-O: the injected command was appended to the existing padding, so its
// removal restores the original layout exactly.
//
// The on-disk file is untouched by design; a running process reads its own
// header from the mapped __TEXT page, not from the container.

static bool is_our_dylib(const struct dylib_command *dc)
{
    // The name is a NUL-terminated string inside the command.
    if (dc->dylib.name.offset >= dc->cmdsize) {
        return false;
    }
    const char *name = (const char *)dc + dc->dylib.name.offset;
    return strstr(name, "FnPatch.dylib") != NULL;
}

void mod_header_scrub_install(void)
{
    if (!fn_cfg_flag("scrub_header", 1)) {
        return;
    }

    struct mach_header_64 *mh = (struct mach_header_64 *)fn_main_header();
    if (!mh || mh->magic != MH_MAGIC_64) {
        FNLOG("scrub: main header is not a 64-bit Mach-O");
        return;
    }

    uint8_t *base = (uint8_t *)mh + sizeof(*mh);
    uint32_t off = 0;
    uint32_t found_off = 0;
    uint32_t found_size = 0;

    for (uint32_t i = 0; i < mh->ncmds; i++) {
        struct load_command *lc = (struct load_command *)(base + off);
        if (lc->cmdsize < sizeof(*lc) || off + lc->cmdsize > mh->sizeofcmds) {
            FNLOG("scrub: load command %u is malformed, stopping", i);
            return;
        }
        if (lc->cmd == LC_LOAD_DYLIB &&
            is_our_dylib((const struct dylib_command *)lc)) {
            found_off  = off;
            found_size = lc->cmdsize;
            break;
        }
        off += lc->cmdsize;
    }

    if (!found_size) {
        FNLOG("scrub: no FnPatch load command found");
        return;
    }

    if (!fn_vm_writable(mh, sizeof(*mh) + mh->sizeofcmds)) {
        FNLOG("scrub: header not writable, load command left in place");
        return;
    }

    size_t tail = mh->sizeofcmds - (found_off + found_size);
    if (tail) {
        memmove(base + found_off, base + found_off + found_size, tail);
    }
    memset(base + mh->sizeofcmds - found_size, 0, found_size);
    mh->ncmds -= 1;
    mh->sizeofcmds -= found_size;

    fn_make_executable(mh, sizeof(*mh) + mh->sizeofcmds + found_size);

    FNLOG("scrub: removed LC_LOAD_DYLIB (%u bytes), ncmds %u sizeofcmds %u",
          found_size, mh->ncmds, mh->sizeofcmds);
}
