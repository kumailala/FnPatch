#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

#include "modules.h"
#include "log.h"
#include "config.h"

/*
 * One-shot "the dylib is alive" alert. The constructor runs long before the
 * game has a window up, so the presentation is retried on the main queue until
 * a view controller exists to present on.
 */

#define FN_POPUP_ATTEMPTS 20

static UIViewController *fn_top_view_controller(void)
{
    UIWindow *key = nil;
    if (@available(iOS 13.0, *)) {
        for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
            if (![scene isKindOfClass:[UIWindowScene class]]) {
                continue;
            }
            for (UIWindow *w in ((UIWindowScene *)scene).windows) {
                if (w.isKeyWindow) {
                    key = w;
                    break;
                }
            }
            if (key) {
                break;
            }
        }
    }
    if (!key) {
        /* keyWindow is deprecated on iOS 13 but remains the only fallback when
         * no scene is connected yet. */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        key = UIApplication.sharedApplication.keyWindow;
#pragma clang diagnostic pop
    }
    if (!key) {
        return nil;
    }
    UIViewController *vc = key.rootViewController;
    while (vc.presentedViewController) {
        vc = vc.presentedViewController;
    }
    return vc;
}

static void fn_popup_try(int attempt)
{
    dispatch_async(dispatch_get_main_queue(), ^{
        UIViewController *top = fn_top_view_controller();
        if (!top) {
            if (attempt < FN_POPUP_ATTEMPTS) {
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)NSEC_PER_SEC),
                               dispatch_get_main_queue(), ^{
                    fn_popup_try(attempt + 1);
                });
            } else {
                FNLOG("popup: no view controller after %d attempts", FN_POPUP_ATTEMPTS);
            }
            return;
        }

        NSString *message =
            [NSString stringWithFormat:@"dylib loaded OK\nFnPatch %s\nlog: Documents/FnPatch.log",
                                       FN_PATCH_VERSION];
        UIAlertController *alert =
            [UIAlertController alertControllerWithTitle:@"FnPatch"
                                                message:message
                                         preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"OK"
                                                 style:UIAlertActionStyleDefault
                                               handler:nil]];
        [top presentViewController:alert animated:YES completion:nil];
        FNLOG("popup: presented on %s", NSStringFromClass([top class]).UTF8String);
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
