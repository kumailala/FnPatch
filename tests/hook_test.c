/*
 * Host-side test for the two pieces of FnPatch that can be verified without a
 * device: the arm64 instruction relocator and the live code patcher.
 *
 * hook.c is included directly so the static encoders/decoders are reachable.
 * Build and run on an arm64 macOS host (the CI runner):
 *     clang -Isrc -o hook_test tests/hook_test.c src/log.c
 *     ./hook_test
 */
#include "../src/hook.c"

#include <stdio.h>
#include <string.h>

static int g_failures;

#define CHECK(cond, fmt, ...)                                              \
    do {                                                                   \
        if (!(cond)) {                                                     \
            printf("FAIL %s:%d  " fmt "\n", __FILE__, __LINE__,            \
                   ##__VA_ARGS__);                                         \
            g_failures++;                                                  \
        }                                                                  \
    } while (0)

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

/* ---- live patching, on real code pages ---------------------------------- */

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

static void test_ret_patch(void)
{
    int (*fn)(void) = probe_value;
    CHECK(fn() == 42, "probe baseline");

    CHECK(fn_patch_ret_w0((void *)fn, 7), "fn_patch_ret_w0 succeeded");
    CHECK(probe_value() == 7, "patched function returns 7");

    CHECK(fn_patch_ret_w0((void *)fn, 0), "fn_patch_ret_w0 second patch");
    CHECK(probe_value() == 0, "patched function returns 0");
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

    CHECK(g_real_sum(2, 3) == 5, "trampoline still computes 5");
    CHECK(probe_sum(2, 3) == 50, "hooked call returns 50");
    CHECK(probe_sum(-4, 1) == -30, "hooked call returns -30");
}

int main(void)
{
    test_relocatable();
    test_adrp();
    test_bcond();
    test_ret_patch();
    test_inline_hook();

    if (g_failures) {
        printf("\n%d check(s) failed\n", g_failures);
        return 1;
    }
    printf("all checks passed\n");
    return 0;
}
