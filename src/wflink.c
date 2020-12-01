#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/wait.h>
#include "stddef.h"
#include <pthread.h>
#include <time.h>
#include <signal.h>
#include <poll.h>

#include "thread_queue.h"
#include "net_timer.h"
#include "wflink.h"
#include "coap_client.h"
#include "http_server.h"

wflink_context_t g_wflink_ctx;
wflink_cfg_t g_wflink_cfg;
int DebugLevel = DEBUG_INFO;

#define WFLINK_DEFAULT_PATH "/config/wflink.cfg"

int init_app()
{
	memset(&g_wflink_ctx, 0 ,sizeof(wflink_context_t));
	g_wflink_ctx.maxConn = 4;
	g_wflink_ctx.maxThread= 4;
	sig_mutex_init(&g_wflink_ctx.coapClient.lock, NULL);
	sig_cond_init(&g_wflink_ctx.coapClient.cond, NULL);
}

int main(int argc, char *argv[])
{
	init_app();
    args_ana(argc, argv);
	load_config(&g_wflink_cfg, g_wflink_ctx.cfgfilename);
    catch_signal();
	g_wflink_ctx.threadPool = init_thread_pool(g_wflink_ctx.maxThread);
	g_wflink_ctx.htimer = timer_init(0, 10, process_task_pool, g_wflink_ctx.threadPool);
	start_coap_client_state_machine(&g_wflink_ctx);
	start_http_server(&g_wflink_ctx, &g_wflink_cfg);
	return 0;
}
