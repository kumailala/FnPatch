#ifndef FNPATCH_MODULES_H
#define FNPATCH_MODULES_H

// Three modules, one job each.
//
// scrub_header  remove our LC_LOAD_DYLIB from the in-memory Mach-O header
// uacslot       swap the UACClient message-gate slot so integrity reports
// never leave the device — this is the kick fix
// popup         an alert proving the dylib loaded
//
// Everything else that used to live here was an inline hook. Inline hooks
// cannot work on this kernel (see hook.h), so they are gone.

void mod_header_scrub_install(void);
void mod_uacslot_install(void);
void mod_popup_install(void);

#endif
