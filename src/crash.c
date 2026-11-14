#include "crash.h"
#include "log.h"

#include <fcntl.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ucontext.h>
#include <unistd.h>

// Fatal-signal reporter.
//
// Everything below runs inside a signal handler, so it obeys three rules:
// no stdio, no malloc, no dyld. The log descriptor, the image table and the
// step ring are all built at install time and only read here. The unwinder is
// a frame-pointer walk with hand-written sanity checks rather than libunwind,
// because libunwind allocates.

#define FN_STEP_MAX      56
#define FN_STEP_SLOTS    8
#define FN_ALTSTACK      (128 * 1024)
#define FN_MAX_IMAGES    24
#define FN_MAX_FRAMES    24

static int  g_fd = -1;

// Step ring: the last few `fn_step` names, oldest first once wrapped.
static char   g_steps[FN_STEP_SLOTS][FN_STEP_MAX];
static int    g_step_count;
static int    g_step_next;

// Pre-resolved image ranges, so the handler never calls into dyld.
typedef struct {
    uintptr_t lo;
    uintptr_t hi;
    char      name[48];
} fn_image;

static fn_image g_images[FN_MAX_IMAGES];
static int      g_image_count;

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
        *p++ = digits[(v >> shift) & 0xFu];
    }
    return p;
}

static char *put_dec(char *p, int v)
{
    char tmp[12];
    int  n = 0;
    if (v < 0) {
        *p++ = '-';
        v = -v;
    }
    do {
        tmp[n++] = (char)('0' + (v % 10));
        v /= 10;
    } while (v);
    while (n) {
        *p++ = tmp[--n];
    }
    return p;
}

// "main+0x1234" / "fnpatch+0x88" / "0x18e31a05c".
static char *put_site(char *p, uintptr_t addr)
{
    for (int i = 0; i < g_image_count; i++) {
        if (addr >= g_images[i].lo && addr < g_images[i].hi) {
            size_t n = strnlen(g_images[i].name, sizeof(g_images[i].name) - 1);
            memcpy(p, g_images[i].name, n);
            p += n;
            *p++ = '+';
            return put_hex(p, (uint64_t)(addr - g_images[i].lo));
        }
    }
    return put_hex(p, (uint64_t)addr);
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

static bool plausible_code(uint64_t a)
{
    return a > 0x1000 && a < 0x0000FFFFFFFFFFFFULL;
}

// Walk x29. Each frame record is {next_fp, return_address}. Bail on anything
// that cannot be a real record: misalignment, a non-increasing fp, or a slot
// that points outside user space. A bad walk must never turn one crash into a
// second one inside the handler.
static void dump_backtrace(uintptr_t fp, uintptr_t sp)
{
    char line[160];
    int  emitted = 0;

    for (int depth = 0; depth < FN_MAX_FRAMES && fp; depth++) {
        if ((fp & 0xF) != 0 && (fp & 0x7) != 0) {
            break;
        }
        if (fp < sp || fp > 0x0000FFFFFFFFFFFFULL || (fp - sp) > (64u << 20)) {
            break;
        }
        const uintptr_t *frame = (const uintptr_t *)fp;
        uintptr_t next = frame[0];
        uintptr_t ret  = frame[1];

        if (!plausible_code(ret)) {
            break;
        }

        char *p = line;
        memcpy(p, "crash:   #", 10);
        p += 10;
        p = put_dec(p, depth);
        *p++ = ' ';
        p = put_site(p, ret);
        *p++ = '\n';
        wr(line, (size_t)(p - line));
        emitted++;

        if (next <= fp) {
            break;
        }
        fp = next;
    }

    if (!emitted) {
        puts_("crash:   (no frame records; built without a frame pointer, "
              "or the stack itself is gone)\n");
    }
}

static void handler(int sig, siginfo_t *si, void *ctx)
{
    uintptr_t pc = 0, lr = 0, fp = 0, sp = 0;

#if defined(__arm64__)
    ucontext_t *uc = (ucontext_t *)ctx;
    if (uc) {
        pc = (uintptr_t)uc->uc_mcontext->__ss.__pc;
        lr = (uintptr_t)uc->uc_mcontext->__ss.__lr;
        fp = (uintptr_t)uc->uc_mcontext->__ss.__fp;
        sp = (uintptr_t)uc->uc_mcontext->__ss.__sp;
    }
#else
    (void)ctx;
#endif

    puts_("\ncrash: --------------------------------------------------------\n");

    char buf[256];
    char *p = buf;

    memcpy(p, "crash: ", 7);
    p += 7;
    const char *name = signal_name(sig);
    size_t nlen = strlen(name);
    memcpy(p, name, nlen);
    p += nlen;

    memcpy(p, " pc=", 4);
    p += 4;
    p = put_site(p, pc);

    memcpy(p, " lr=", 4);
    p += 4;
    p = put_site(p, lr);

    *p++ = '\n';
    wr(buf, (size_t)(p - buf));

    p = buf;
    memcpy(p, "crash: addr=", 12);
    p += 12;
    p = put_site(p, (uintptr_t)(si ? si->si_addr : NULL));
    memcpy(p, " sp=", 4);
    p += 4;
    p = put_hex(p, (uint64_t)sp);
    memcpy(p, " fp=", 4);
    p += 4;
    p = put_hex(p, (uint64_t)fp);
    *p++ = '\n';
    wr(buf, (size_t)(p - buf));

    // Steps oldest -> newest, so the last line is the one that was running.
    int first = g_step_count < FN_STEP_SLOTS ? 0 : g_step_next;
    for (int i = 0; i < g_step_count; i++) {
        int idx = (first + i) % FN_STEP_SLOTS;
        p = buf;
        memcpy(p, "crash: step was ", 16);
        p += 16;
        size_t n = strnlen(g_steps[idx], FN_STEP_MAX - 1);
        memcpy(p, g_steps[idx], n);
        p += n;
        *p++ = '\n';
        wr(buf, (size_t)(p - buf));
    }

    dump_backtrace(fp, sp);
    puts_("crash: --------------------------------------------------------\n");

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
    char *slot = g_steps[g_step_next];
    for (; i < n; i++) {
        slot[i] = name[i];
    }
    slot[i] = '\0';

    g_step_next = (g_step_next + 1) % FN_STEP_SLOTS;
    if (g_step_count < FN_STEP_SLOTS) {
        g_step_count++;
    }

    FNLOG("step: %s", slot);
}

// __TEXT of one loaded image, resolved once at install time.
static bool text_range(const struct mach_header *mh, intptr_t slide,
                       uintptr_t *lo, uintptr_t *hi)
{
    if (!mh || mh->magic != MH_MAGIC_64) {
        return false;
    }
    const struct mach_header_64 *h = (const struct mach_header_64 *)mh;
    const uint8_t *cmd = (const uint8_t *)h + sizeof(*h);

    for (uint32_t k = 0; k < h->ncmds; k++) {
        const struct load_command *lc = (const struct load_command *)cmd;
        if (lc->cmdsize < sizeof(*lc)) {
            return false;
        }
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *sg = (const struct segment_command_64 *)lc;
            if (strncmp(sg->segname, "__TEXT", sizeof(sg->segname)) == 0) {
                *lo = (uintptr_t)slide + (uintptr_t)sg->vmaddr;
                *hi = *lo + (uintptr_t)sg->vmsize;
                return true;
            }
        }
        cmd += lc->cmdsize;
    }
    return false;
}

static void build_image_table(void)
{
    uint32_t n = _dyld_image_count();

    for (uint32_t i = 0; i < n && g_image_count < FN_MAX_IMAGES; i++) {
        const struct mach_header *mh = _dyld_get_image_header(i);
        uintptr_t lo = 0, hi = 0;
        if (!text_range(mh, _dyld_get_image_vmaddr_slide(i), &lo, &hi)) {
            continue;
        }

        const char *path = _dyld_get_image_name(i);
        const char *base = path ? strrchr(path, '/') : NULL;
        base = base ? base + 1 : (path ? path : "?");

        fn_image *e = &g_images[g_image_count];
        e->lo = lo;
        e->hi = hi;
        strncpy(e->name, base, sizeof(e->name) - 1);
        e->name[sizeof(e->name) - 1] = '\0';

        // Trailing .dylib is noise in a one-word label.
        size_t len = strlen(e->name);
        if (len > 6 && strcmp(e->name + len - 6, ".dylib") == 0) {
            e->name[len - 6] = '\0';
        }
        g_image_count++;
    }
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

    build_image_table();
    fn_step("boot");

    stack_t ss;
    memset(&ss, 0, sizeof(ss));
    void *alt = mmap(NULL, FN_ALTSTACK, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANON, -1, 0);
    if (alt != MAP_FAILED) {
        ss.ss_sp    = alt;
        ss.ss_size  = FN_ALTSTACK;
        ss.ss_flags = 0;
        if (sigaltstack(&ss, NULL) != 0) {
            FNLOG("crash: sigaltstack refused");
        }
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = handler;
    // SA_NODEFER so a fault raised inside this handler is not blocked into a
    // silent hang: it re-enters once, the write fails, and the second raise
    // with SIG_DFL still produces a normal system crash report.
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_NODEFER;
    sigemptyset(&sa.sa_mask);

    static const int sigs[] = { SIGSEGV, SIGBUS, SIGILL, SIGFPE, SIGABRT, SIGTRAP };
    for (size_t i = 0; i < sizeof(sigs) / sizeof(sigs[0]); i++) {
        if (sigaction(sigs[i], &sa, NULL) != 0) {
            FNLOG("crash: sigaction %d failed", sigs[i]);
        }
    }

    FNLOG("crash: reporter armed, %d images indexed, backtrace via frame records",
          g_image_count);
}
