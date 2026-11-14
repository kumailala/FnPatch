#include "hook.h"
#include "log.h"

#include <mach/mach.h>
#include <mach-o/dyld.h>
#include <sys/mman.h>
#include <unistd.h>

static size_t page_size_cached(void)
{
    static size_t cached;
    if (!cached) {
        int ps = getpagesize();
        cached = ps > 0 ? (size_t)ps : 16384;
    }
    return cached;
}

/* Round [addr, addr+len) out to whole pages. */
static void page_span(void *addr, size_t len, uintptr_t *page, size_t *size)
{
    size_t ps = page_size_cached();
    *page = (uintptr_t)addr & ~(uintptr_t)(ps - 1);
    size_t off = (uintptr_t)addr - *page;
    *size = ((off + len + ps - 1) / ps) * ps;
}

bool fn_vm_writable(void *addr, size_t len)
{
    uintptr_t page;
    size_t size;
    page_span(addr, len, &page, &size);

    kern_return_t kr = vm_protect(mach_task_self(), page, size, false,
                                  VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr != KERN_SUCCESS) {
        FNLOG("vm_protect(RW) failed at %p (0x%x)", addr, kr);
        return false;
    }
    return true;
}

/*
 * Read+execute restore, with the fallbacks that exist because the primary
 * request is not always honoured:
 *
 *   1. vm_protect R|X        the correct answer
 *   2. vm_protect R|W|X      keeps execute when R|X is refused
 *   3. mprotect(PROT_EXEC)   a different path to the same protection
 *
 * The return value matters. Callers must treat false as "this page is dead,
 * do not execute anything on it" rather than logging and carrying on.
 */
bool fn_make_executable_ok(void *addr, size_t len)
{
    uintptr_t page;
    size_t size;
    page_span(addr, len, &page, &size);

    kern_return_t kr = vm_protect(mach_task_self(), page, size, false,
                                  VM_PROT_READ | VM_PROT_EXECUTE);
    if (kr == KERN_SUCCESS) {
        return true;
    }

    kern_return_t krw = vm_protect(mach_task_self(), page, size, false,
                                   VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
    if (krw == KERN_SUCCESS) {
        FNLOG("make_executable: %p kept RWX (R|X refused 0x%x)", addr, kr);
        return true;
    }

    if (mprotect((void *)page, size, PROT_READ | PROT_EXEC) == 0) {
        FNLOG("make_executable: %p restored via mprotect (vm_protect 0x%x/0x%x)",
              addr, kr, krw);
        return true;
    }

    FNLOG("make_executable: FAILED at %p (0x%x/0x%x) page left writable and "
          "non-executable", addr, kr, krw);
    return false;
}

void fn_make_executable(void *addr, size_t len)
{
    (void)fn_make_executable_ok(addr, len);
}

void fn_make_readonly(void *addr, size_t len)
{
    uintptr_t page;
    size_t size;
    page_span(addr, len, &page, &size);

    if (vm_protect(mach_task_self(), page, size, false, VM_PROT_READ) == KERN_SUCCESS) {
        return;
    }
    if (mprotect((void *)page, size, PROT_READ) == 0) {
        return;
    }
    FNLOG("make_readonly: FAILED at %p, page left writable", addr);
}

void *fn_main_header(void)
{
    return (void *)_dyld_get_image_header(0);
}

uintptr_t fn_main_slide(void)
{
    return (uintptr_t)_dyld_get_image_vmaddr_slide(0);
}
