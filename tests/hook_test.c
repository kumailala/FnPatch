/*
 * Host-side test for the two pieces of FnPatch that can be checked without a
 * device: the arm64 instruction relocator/encoder, and the bytes the live code
 * patcher writes.
 *
 * hook.c is included directly so the static encoders/decoders are reachable.
 * Build and run on an arm64 macOS host (the CI runner):
 *     clang -Isrc -o hook_test tests/hook_test.c src/log.c
 *     ./hook_test
 *
 * Executing a modified code page is refused by arm64 macOS unless the process
 * holds a JIT entitlement, so the calls into patched code are guarded: a fault
 * there is reported as SKIP (platform), not as a failure. The byte checks are
 * unconditional and cover everything except the CPU actually running the patch.
 */
#include "../src/hook.c"

#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int g_failures;
static int g_skips;

#define CHECK(cond, fmt, ...)                                              \
    do {                                                                   \
        if (!(cond)) {                                                     \
            printf("FAIL %s:%d  " fmt "\n", __FILE__, __LINE__,            \
                   ##__VA_ARGS__);                                         \
            g_failures++;                                                  \
        }                                                                  \
    } while (0)

/* ---- guarded execution ------------------------------------------------- */

static sigjmp_buf         g_jmp;
static volatile sig_atomic_t g_guarded;

static void fault_handler(int sig)
{
    if (g_guarded) {
        g_guarded = 0;
        siglongjmp(g_jmp, 1);
    }
    _exit(2);
}

static void install_fault_handlers(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = fault_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_NODEFER;
    sigaction(SIGBUS, &sa, NULL);
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGILL, &sa, NULL);
    sigaction(SIGTRAP, &sa, NULL);
}

/* Returns 0 when the call completed, 1 when the platform refused it. */
static int run_guarded(void (*body)(void))
{
    if (sigsetjmp(g_jmp, 1) == 0) {
        g_guarded = 1;
        body();
        g_guarded = 0;
        return 0;
    }
    g_guarded = 0;
    return 1;
}

/* ---- pure encoding tests ----------------------------------------------- */

static uintptr_t adrp_target(uint32_t insn, uintptr_t pc)
{
    int64_t imm = decode_imm21(insn);
    return (pc & ~(uintptr_t)0xFFF) + ((uintptr_t)imm << 12);
}

static uintptr_t imm19_target(uint32_t insn, uintptr_t pc)
{
    int64_t imm = (int64_t)((insn >> 5) & 0x7FFFF);
    if (imm & (1LL << 18)) {
        imm -= (1LL << 19);
    }
    return pc + ((uintptr_t)imm * 4);
}

static void test_adrp(void)
{
    const uintptr_t from   = 0x100000000ULL;
    const uintptr_t target = 0x1000A0000ULL;   /* +0xA0 pages */
    int64_t pages = (int64_t)((target & ~(uintptr_t)0xFFF) -
                              (from   & ~(uintptr_t)0xFFF)) >> 12;

    uint32_t adrp = encode_adrp(0x90000000u, pages);
    CHECK(adrp_target(adrp, from) == target, "adrp encode round trip");

    const uintptr_t to = from + 0x4000000ULL;
    bool ok = false;
    uint32_t moved = relocate(adrp, from, to, &ok);
    CHECK(ok, "adrp relocate ok");
    CHECK(adrp_target(moved, to) == target, "adrp retarget after move");

    /* Same page must stay put when relocated within the page. */
    moved = relocate(adrp, from, from + 0x800, &ok);
    CHECK(ok, "adrp relocate in-page ok");
    CHECK(adrp_target(moved, from + 0x800) == target, "adrp in-page retarget");
}

static void test_bcond(void)
{
    const uintptr_t from   = 0x100000000ULL;
    const uintptr_t target = from + 0x400;      /* 256 insns ahead */
    int64_t slots = ((int64_t)target - (int64_t)from) >> 2;
    uint32_t bcond = (uint32_t)(0x54000000u | ((slots & 0x7FFFF) << 5) | 0x1u);

    CHECK(imm19_target(bcond, from) == target, "b.cond encode round trip");

    const uintptr_t to = from - 0x10000;
    bool ok = false;
    uint32_t moved = relocate(bcond, from, to, &ok);
    CHECK(ok, "b.cond relocate ok");
    CHECK(imm19_target(moved, to) == target, "b.cond retarget");
}

static void test_relocatable(void)
{
    CHECK(relocatable(0xD503201F /* nop */), "nop is relocatable");
    CHECK(relocatable(0xA9BF7BFD /* stp x29,x30,[sp,#-16]! */), "stp is relocatable");
    CHECK(!relocatable(0x94000000 /* bl */), "bl refused");
    CHECK(!relocatable(0x14000000 /* b  */), "b refused");
}

/* ---- live patching, on real code pages --------------------------------- */

__attribute__((noinline))
static int probe_value(void)
{
    volatile int marker = 42;
    return marker;
}

__attribute__((noinline))
static int probe_sum(int a, int b)
{
    volatile int bias = 0;
    return a + b + bias;
}

static int (*g_real_sum)(int, int);

static int hook_sum(int a, int b)
{
    return g_real_sum(a, b) * 10;
}

static volatile int g_calls;

static void call_probe(void)     { g_calls += probe_value(); }
static void call_trampoline(void){ g_calls += g_real_sum(2, 3); }
static void call_hooked(void)    { g_calls += probe_sum(-4, 1); }

static void test_ret_patch(void)
{
    int (*fn)(void) = probe_value;
    uint32_t before[2];
    memcpy(before, (void *)fn, sizeof(before));
    CHECK(fn() == 42, "probe baseline");

    CHECK(fn_patch_ret_w0((void *)fn, 7), "fn_patch_ret_w0 succeeded");

    /* What was actually written, read back without executing it. */
    uint32_t after[2];
    memcpy(after, (void *)fn, sizeof(after));
    CHECK(after[0] == (A64_MOV_W0_0 | (7u << 5)), "mov w0,#7 encoded (0x%08x)",
          after[0]);
    CHECK(after[1] == A64_RET, "ret encoded (0x%08x)", after[1]);
    CHECK(memcmp(before, after, sizeof(after)) != 0, "entry bytes changed");

    if (run_guarded(call_probe)) {
        printf("SKIP ret patch: platform refuses to execute a modified code page\n");
        g_skips++;
    } else {
        CHECK(g_calls == 7, "patched function returns 7 (got %d)", g_calls);
    }
    g_calls = 0;
}

static void test_inline_hook(void)
{
    void *tramp = NULL;
    if (!fn_hook_inline((void *)probe_sum, (void *)hook_sum, &tramp)) {
        printf("FAIL inline hook install\n");
        g_failures++;
        return;
    }
    g_real_sum = (int (*)(int, int))tramp;

    /* Entry now branches through x16 to the handler. */
    uint32_t entry[4];
    memcpy(entry, (void *)probe_sum, sizeof(entry));
    CHECK(entry[0] == A64_LDR_X16_8, "entry loads handler (0x%08x)", entry[0]);
    CHECK(entry[1] == A64_BR_X16, "entry branches (0x%08x)", entry[1]);
    uintptr_t handler = 0;
    memcpy(&handler, &entry[2], sizeof(handler));
    CHECK(handler == (uintptr_t)hook_sum, "handler address is exact");

    /* Trampoline ends with a branch back to target+16. */
    uint32_t tail[4];
    memcpy(tail, (uint32_t *)tramp + 4, sizeof(tail));
    CHECK(tail[0] == A64_LDR_X16_8, "trampoline loads return (0x%08x)", tail[0]);
    CHECK(tail[1] == A64_BR_X16, "trampoline branches (0x%08x)", tail[1]);
    uintptr_t back = 0;
    memcpy(&back, &tail[2], sizeof(back));
    CHECK(back == (uintptr_t)probe_sum + 16, "trampoline returns to target+16");

    if (run_guarded(call_trampoline) || run_guarded(call_hooked)) {
        printf("SKIP inline hook calls: platform refuses to execute modified code\n");
        g_skips++;
        return;
    }
    CHECK(g_calls == 5 + 50, "trampoline 5 + hooked 50 (got %d)", g_calls);
    g_calls = 0;
}

int main(void)
{
    install_fault_handlers();

    test_relocatable();
    test_adrp();
    test_bcond();
    test_ret_patch();
    test_inline_hook();

    if (g_failures) {
        printf("\n%d check(s) failed\n", g_failures);
        return 1;
    }
    printf("all checks passed (%d skipped on this platform)\n", g_skips);
    return 0;
}
