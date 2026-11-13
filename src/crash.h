#ifndef FNPATCH_CRASH_H
#define FNPATCH_CRASH_H

/*
 * Fatal-signal reporter. Writes one line to the log with the signal, the fault
 * address, the program counter, the link register and the step that was
 * running, then restores the default handler and re-raises, so the system
 * still sees a normal crash.
 *
 * Everything here is async-signal-safe: write(2) on a descriptor opened at
 * install time, a hand-rolled hex formatter, no malloc, no stdio.
 */
void fn_crash_install(void);

/* Name the operation about to run. Logged immediately, and repeated in the
 * crash line if the process dies before the next step. */
void fn_step(const char *name);

#endif
