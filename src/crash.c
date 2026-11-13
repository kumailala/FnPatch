#include "crash.h"
#include "log.h"

#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ucontext.h>
#include <unistd.h>

#define FN_STEP_MAX 80
#define FN_ALTSTACK (64 * 1024)

static int  g_fd = -1;
static char g_step[FN_STEP_MAX] = "boot";

static void wr(const char *s, size_t n)
{
    if (g_fd < 0) {
        return;
    }
    while (n) {
        ssize_t w = write(g_fd, s, n);
        if (w <= 0) {
            return;
        }
        s += (size_t)w;
        n -= (size_t)w;
    }
}

static void puts_(const char *s)
{
    wr(s, strlen(s));
}

static char *put_hex(char *p, uint64_t v)
{
    static const char digits[] = "0123456789abcdef";
    *p++ = '0';
    *p++ = 'x';
    for (int shift = 60; shift >= 0; shift -= 4) {
        *p++ = digits[(v >> shift) & 0xF];
    }
    return p;
}

static const char *signal_name(int sig)
{
    switch (sig) {
    case SIGSEGV: return "SIGSEGV";
    case SIGBUS:  return "SIGBUS";
    case SIGILL:  return "SIGILL";
    case SIGFPE:  return "SIGFPE";
    case SIGABRT: return "SIGABRT";
    case SIGTRAP: return "SIGTRAP";
    default:      return "SIG?";
    }
}

static void handler(int sig, siginfo_t *si, void *ctx)
{
    uintptr_t pc = 0;
    uintptr_t lr = 0;

#if defined(__arm64__)
    ucontext_t *uc = (ucontext_t *)ctx;
    if (uc) {
        pc = (uintptr_t)uc->uc_mcontext->__ss.__pc;
        lr = (uintptr_t)uc->uc_mcontext->__ss.__lr;
    }
#else
    (void)ctx;
#endif

    char buf[256];
    char *p = buf;

    memcpy(p, "\ncrash: ", 8);
    p += 8;
    const char *name = signal_name(sig);
    size_t nlen = strlen(name);
    memcpy(p, name, nlen);
    p += nlen;

    memcpy(p, " pc=", 4);
    p += 4;
    p = put_hex(p, (uint64_t)pc);

    memcpy(p, " lr=", 4);
    p += 4;
    p = put_hex(p, (uint64_t)lr);

    memcpy(p, " addr=", 6);
    p += 6;
    p = put_hex(p, (uint64_t)(uintptr_t)(si ? si->si_addr : NULL));

    memcpy(p, " step=", 6);
    p += 6;
    size_t slen = strnlen(g_step, FN_STEP_MAX - 1);
    memcpy(p, g_step, slen);
    p += slen;

    *p++ = '\n';

    /* pc is written twice: raw, and as the offset from the main executable's
     * header when it falls inside it, which is what the ret* keys want. */
    wr(buf, (size_t)(p - buf));

    signal(sig, SIG_DFL);
    raise(sig);
}

void fn_step(const char *name)
{
    if (!name) {
        return;
    }
    size_t n = strnlen(name, FN_STEP_MAX - 1);
    size_t i = 0;
    for (; i < n; i++) {
        g_step[i] = name[i];
    }
    g_step[i] = '\0';
    FNLOG("step: %s", g_step);
}

void fn_crash_install(void)
{
    if (!fn_cfg_flag("crash", 1)) {
        FNLOG("crash: reporter disabled by config");
        return;
    }

    const char *path = fn_log_path();
    g_fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (g_fd < 0) {
        FNLOG("crash: cannot open log for append, reporter inactive");
        return;
    }

    stack_t ss;
    memset(&ss, 0, sizeof(ss));
    void *alt = mmap(NULL, FN_ALTSTACK, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANON, -1, 0);
    if (alt != MAP_FAILED) {
        ss.ss_sp   = alt;
        ss.ss_size = FN_ALTSTACK;
        ss.ss_flags = 0;
        if (sigaltstack(&ss, NULL) != 0) {
            FNLOG("crash: sigaltstack refused");
        }
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = handler;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_NODEFER;
    sigemptyset(&sa.sa_mask);

    static const int sigs[] = { SIGSEGV, SIGBUS, SIGILL, SIGFPE, SIGABRT, SIGTRAP };
    for (size_t i = 0; i < sizeof(sigs) / sizeof(sigs[0]); i++) {
        if (sigaction(sigs[i], &sa, NULL) != 0) {
            FNLOG("crash: sigaction %d failed", sigs[i]);
        }
    }

    FNLOG("crash: reporter armed");
}
