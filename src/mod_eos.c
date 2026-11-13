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

static poll_status_t g_real_poll;
static session_t    g_real_begin;
static recv_server_t g_real_recv;

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
    (void)handle;
    (void)message;
    return 0;
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
        FNLOG("eos: ReceiveMessageFromServer hooked");
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
