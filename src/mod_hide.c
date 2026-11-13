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
 */

#define FN_MAX_IMAGES 1024

typedef uint32_t (*fn_image_count_t)(void);
typedef const char *(*fn_image_name_t)(uint32_t);
typedef const void *(*fn_image_header_t)(uint32_t);

static uint32_t          g_visible_count;
static const char       *g_visible_names[FN_MAX_IMAGES];
static const void       *g_visible_headers[FN_MAX_IMAGES];

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

static uint32_t hook_count(void)
{
    return g_visible_count;
}

static const char *hook_name(uint32_t index)
{
    if (index >= g_visible_count) {
        return NULL;
    }
    return g_visible_names[index];
}

static const void *hook_header(uint32_t index)
{
    if (index >= g_visible_count) {
        return NULL;
    }
    return g_visible_headers[index];
}

void mod_hide_install(void)
{
    if (!fn_cfg_flag("hide_images", 1)) {
        return;
    }

    g_real_count  = (fn_image_count_t)(void *)&_dyld_image_count;
    g_real_name   = (fn_image_name_t)(void *)&_dyld_get_image_name;
    g_real_header = (fn_image_header_t)(void *)&_dyld_get_image_header;

    uint32_t total = g_real_count();
    if (total > FN_MAX_IMAGES) {
        total = FN_MAX_IMAGES;
    }

    int hidden = 0;
    for (uint32_t i = 0; i < total; i++) {
        const char *name   = g_real_name(i);
        const void *header = g_real_header(i);
        if (should_hide(name)) {
            FNLOG("hide: %u %s", i, name ? name : "(null)");
            hidden++;
            continue;
        }
        g_visible_names[g_visible_count]   = name;
        g_visible_headers[g_visible_count] = header;
        g_visible_count++;
    }

    void *tramp = NULL;
    if (!fn_hook_inline((void *)g_real_count, (void *)hook_count, &tramp)) {
        FNLOG("hide: count hook failed");
        return;
    }
    if (!fn_hook_inline((void *)g_real_name, (void *)hook_name, &tramp)) {
        FNLOG("hide: name hook failed");
        return;
    }
    if (!fn_hook_inline((void *)g_real_header, (void *)hook_header, &tramp)) {
        FNLOG("hide: header hook failed");
        return;
    }

    FNLOG("hide: %u visible / %u total (%d hidden)", g_visible_count, total, hidden);
}
