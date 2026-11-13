#include "modules.h"
#include "hook.h"
#include "log.h"
#include "config.h"

#include <pthread.h>
#include <string.h>
#include <time.h>

/*
 * EOSSDK is dlopen'd after us, so the anti-cheat entry points are resolved on
 * a retry thread rather than at constructor time.
 *
 * EOS_EAntiCheatClientViolationType: 0 == EOS_ACCVT_NoViolation
 * EOS_EResult:                       0 == EOS_Success
 */

typedef int32_t (*poll_status_t)(void *, int32_t *);
typedef int32_t (*session_t)(const void *);
typedef int32_t (*recv_server_t)(void *, const void *);
typedef uint64_t (*notify_t)(void *, const void *, void *, void *);

static poll_status_t g_real_poll;
static session_t    g_real_begin;
static recv_server_t g_real_recv;
static bool          g_drop_server;

/*
 * The integrity-violation and peer-action notifications are the SDK's way of
 * telling the game that the client failed its own check. Registering nothing
 * means the callback never runs, so the kick path never gets its input while
 * the rest of the anti-cheat client keeps talking to the service normally.
 * Returns EOS_INVALID_NOTIFICATIONID (0).
 */
static uint64_t hook_notify_integrity(void *handle, const void *options,
                                      void *client_data, void *callback)
{
    (void)handle;
    (void)options;
    (void)client_data;
    (void)callback;
    FNLOG("eos: AddNotifyClientIntegrityViolated swallowed");
    return 0;
}

static uint64_t hook_notify_peer_action(void *handle, const void *options,
                                        void *client_data, void *callback)
{
    (void)handle;
    (void)options;
    (void)client_data;
    (void)callback;
    FNLOG("eos: AddNotifyPeerActionRequired swallowed");
    return 0;
}

static int32_t hook_poll_status(void *handle, int32_t *violation)
{
    int32_t rc = g_real_poll ? g_real_poll(handle, violation) : 0;
    (void)rc;
    if (violation) {
        if (*violation != 0) {
            FNLOG("eos: violation %d suppressed", (int)*violation);
        }
        *violation = 0;
    }
    return 0;
}

static int32_t hook_begin_session(const void *options)
{
    if (g_real_begin) {
        (void)g_real_begin(options);
    }
    FNLOG("eos: AntiCheat BeginSession -> EOS_Success");
    return 0;
}

static int32_t hook_recv_server(void *handle, const void *message)
{
    if (g_drop_server) {
        return 0;
    }
    return g_real_recv ? g_real_recv(handle, message) : 0;
}

static bool install_eos(void)
{
    void *poll = fn_sym("EOS_AntiCheatClient_PollStatus");
    if (!poll) {
        return false;
    }

    void *tramp = NULL;
    if (!fn_hook_inline(poll, (void *)hook_poll_status, (void **)&g_real_poll)) {
        FNLOG("eos: PollStatus hook failed");
        return false;
    }
    FNLOG("eos: PollStatus hooked");

    void *begin = fn_sym("EOS_AntiCheatClient_BeginSession");
    if (begin && fn_hook_inline(begin, (void *)hook_begin_session, (void **)&g_real_begin)) {
        FNLOG("eos: BeginSession hooked");
    }
    void *recv = fn_sym("EOS_AntiCheatClient_ReceiveMessageFromServer");
    if (recv && fn_hook_inline(recv, (void *)hook_recv_server, (void **)&g_real_recv)) {
        g_drop_server = fn_cfg_flag("eos_drop_server", 0) != 0;
        FNLOG("eos: ReceiveMessageFromServer hooked (drop=%d)", g_drop_server ? 1 : 0);
    }

    void *ig = fn_sym("EOS_AntiCheatClient_AddNotifyClientIntegrityViolated");
    if (ig) {
        void *unused = NULL;
        if (fn_hook_inline(ig, (void *)hook_notify_integrity, &unused)) {
            FNLOG("eos: AddNotifyClientIntegrityViolated hooked");
        } else {
            FNLOG("eos: AddNotifyClientIntegrityViolated hook failed");
        }
    } else {
        FNLOG("eos: AddNotifyClientIntegrityViolated absent");
    }

    void *pa = fn_sym("EOS_AntiCheatClient_AddNotifyPeerActionRequired");
    if (pa) {
        void *unused = NULL;
        if (fn_hook_inline(pa, (void *)hook_notify_peer_action, &unused)) {
            FNLOG("eos: AddNotifyPeerActionRequired hooked");
        } else {
            FNLOG("eos: AddNotifyPeerActionRequired hook failed");
        }
    } else {
        FNLOG("eos: AddNotifyPeerActionRequired absent");
    }

    (void)tramp;
    return true;
}

static void *eos_watchdog(void *arg)
{
    (void)arg;
    for (int i = 0; i < 240; i++) { /* 60 s at 250 ms */
        if (install_eos()) {
            FNLOG("eos: installed after %d ticks", i);
            return NULL;
        }
        struct timespec ts = { 0, 250 * 1000 * 1000 };
        nanosleep(&ts, NULL);
    }
    FNLOG("eos: EOSSDK never exposed the anti-cheat client");
    return NULL;
}

void mod_eos_install(void)
{
    if (!fn_cfg_flag("eos", 1)) {
        return;
    }
    if (install_eos()) {
        return;
    }
    pthread_t th;
    if (pthread_create(&th, NULL, eos_watchdog, NULL) == 0) {
        pthread_detach(th);
        FNLOG("eos: waiting for EOSSDK");
    }
}
