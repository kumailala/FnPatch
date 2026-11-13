#include "modules.h"
#include "hook.h"
#include "log.h"
#include "config.h"

#include <mach-o/dyld.h>
#include <string.h>

/*
 * The integrity check walks the loaded image list looking for injected
 * libraries. We give it the same list minus our own entries, with indices
 * remapped so an index returned by count() is always valid for name().
 *
 * The real functions are resolved with dlsym. Taking the address of
 * &_dyld_image_count inside this dylib would only reach our own import stub,
 * so patching that would filter this dylib's calls and nobody else's.
 *
 * The list is filtered live rather than snapshotted, so images loaded later
 * (EOSSDK, Metal shader caches) still show up with correct indices.
 */

#define FN_MAX_IMAGES 4096

typedef uint32_t (*fn_image_count_t)(void);
typedef const char *(*fn_image_name_t)(uint32_t);
typedef const void *(*fn_image_header_t)(uint32_t);

static fn_image_count_t  g_real_count;
static fn_image_name_t   g_real_name;
static fn_image_header_t g_real_header;

static const char *const g_blocked[] = FN_HIDE_PATTERNS_INIT;

static bool should_hide(const char *name)
{
    if (!name) {
        return false;
    }
    for (size_t i = 0; i < sizeof(g_blocked) / sizeof(g_blocked[0]); i++) {
        if (strstr(name, g_blocked[i])) {
            return true;
        }
    }
    return false;
}

static uint32_t real_total(void)
{
    uint32_t total = g_real_count();
    return total > FN_MAX_IMAGES ? FN_MAX_IMAGES : total;
}

/* Real index of the index-th visible image, or false when out of range. */
static bool map_index(uint32_t visible_index, uint32_t *real_index)
{
    uint32_t seen = 0;
    uint32_t total = real_total();
    for (uint32_t i = 0; i < total; i++) {
        if (should_hide(g_real_name(i))) {
            continue;
        }
        if (seen == visible_index) {
            *real_index = i;
            return true;
        }
        seen++;
    }
    return false;
}

static uint32_t hook_count(void)
{
    uint32_t seen = 0;
    uint32_t total = real_total();
    for (uint32_t i = 0; i < total; i++) {
        if (!should_hide(g_real_name(i))) {
            seen++;
        }
    }
    return seen;
}

static const char *hook_name(uint32_t index)
{
    uint32_t real = 0;
    if (!map_index(index, &real)) {
        return NULL;
    }
    return g_real_name(real);
}

static const void *hook_header(uint32_t index)
{
    uint32_t real = 0;
    if (!map_index(index, &real)) {
        return NULL;
    }
    return g_real_header(real);
}

static void *resolve(const char *name)
{
    void *p = fn_sym(name);
    if (!p) {
        FNLOG("hide: %s unresolved", name);
    }
    return p;
}

void mod_hide_install(void)
{
    if (!fn_cfg_flag("hide_images", 1)) {
        return;
    }

    g_real_count  = (fn_image_count_t)resolve("_dyld_image_count");
    g_real_name   = (fn_image_name_t)resolve("_dyld_get_image_name");
    g_real_header = (fn_image_header_t)resolve("_dyld_get_image_header");
    if (!g_real_count || !g_real_name || !g_real_header) {
        FNLOG("hide: image list unavailable, nothing hidden");
        return;
    }

    uint32_t total = real_total();
    int hidden = 0;
    for (uint32_t i = 0; i < total; i++) {
        const char *name = g_real_name(i);
        if (should_hide(name)) {
            FNLOG("hide: %u %s", i, name ? name : "(null)");
            hidden++;
        }
    }

    /* Header and name first: if the count hook is the one that fails, the list
     * still answers correctly for every index below the real count. */
    void *tramp = NULL;
    FNLOG("hide: hooking _dyld_get_image_header");
    if (!fn_hook_inline((void *)g_real_header, (void *)hook_header, &tramp)) {
        FNLOG("hide: header hook failed, list left untouched");
        return;
    }
    FNLOG("hide: hooking _dyld_get_image_name");
    if (!fn_hook_inline((void *)g_real_name, (void *)hook_name, &tramp)) {
        FNLOG("hide: name hook failed, count left untouched");
        return;
    }
    FNLOG("hide: hooking _dyld_image_count");
    if (!fn_hook_inline((void *)g_real_count, (void *)hook_count, &tramp)) {
        FNLOG("hide: count hook failed, %d image(s) hidden", hidden);
        return;
    }

    FNLOG("hide: %d hidden of %u images", hidden, total);
}
