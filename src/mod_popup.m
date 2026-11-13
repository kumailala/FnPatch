#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

#include "modules.h"
#include "log.h"
#include "config.h"

/*
 * One-shot "the dylib is alive" alert.
 *
 * Presented from a window of our own at alert level rather than from the
 * game's view controller: during launch the game's root controller is usually
 * mid-transition, and a presentation on top of that silently does nothing.
 *
 * The constructor runs before any scene is connected, so it retries once a
 * second until one exists.
 */

#define FN_POPUP_ATTEMPTS 60

static UIWindow *g_alert_window;

static UIWindowScene *fn_active_scene(void)
{
    if (@available(iOS 13.0, *)) {
        for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
            if (![scene isKindOfClass:[UIWindowScene class]]) {
                continue;
            }
            if (scene.activationState == UISceneActivationStateForegroundActive) {
                return (UIWindowScene *)scene;
            }
        }
        for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
            if ([scene isKindOfClass:[UIWindowScene class]]) {
                return (UIWindowScene *)scene;
            }
        }
    }
    return nil;
}

static void fn_popup_show(void)
{
    UIWindowScene *scene = fn_active_scene();
    if (!scene) {
        return;
    }

    if (!g_alert_window) {
        g_alert_window = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
        g_alert_window.windowLevel = UIWindowLevelAlert + 1;
        g_alert_window.rootViewController = [[UIViewController alloc] init];
    }
    g_alert_window.windowScene = scene;
    g_alert_window.hidden = NO;

    NSString *message =
        [NSString stringWithFormat:@"dylib loaded OK\nFnPatch %s\nlog: Documents/FnDiag/FnPatch.log",
                                   FN_PATCH_VERSION];
    UIAlertController *alert =
        [UIAlertController alertControllerWithTitle:@"FnPatch"
                                            message:message
                                     preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"OK"
                                             style:UIAlertActionStyleDefault
                                           handler:^(UIAlertAction *action) {
        (void)action;
        g_alert_window.hidden = YES;
    }]];
    [g_alert_window.rootViewController presentViewController:alert animated:YES completion:nil];
    FNLOG("popup: presented (%s)", NSStringFromClass([scene class]).UTF8String);
}

static void fn_popup_try(int attempt)
{
    dispatch_async(dispatch_get_main_queue(), ^{
        if (fn_active_scene()) {
            fn_popup_show();
            return;
        }
        if (attempt < FN_POPUP_ATTEMPTS) {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)NSEC_PER_SEC),
                           dispatch_get_main_queue(), ^{
                fn_popup_try(attempt + 1);
            });
        } else {
            FNLOG("popup: no window scene after %d attempts", FN_POPUP_ATTEMPTS);
        }
    });
}

void mod_popup_install(void)
{
    if (!fn_cfg_flag("popup", 1)) {
        FNLOG("popup: disabled by config");
        return;
    }
    fn_popup_try(0);
}
