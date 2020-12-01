#include <stdio.h>  
#include <stdlib.h>  
#include <errno.h>  
#include <string.h>  
#include <unistd.h>  
#include <sys/types.h>  
#include "stddef.h"
#include <pthread.h>
#include <time.h>
#include <signal.h>
#include "state_machine.h"

/* State Machine Interfaces
 *	void *init_state_machine(state_process *processes, int state_num);
 *	int enqueue_state_machine(void *state_machine, unsigned int state);
 *	void destroy_state_machine(void *state_machine);
 */

enum state_type_e
{
	STATE_INIT,
	STATE_CONN,
	STATE_SESSIONTIMEOUT,
};

static int handle_state_init()
{
	printf("enter %s\n", __FUNCTION__);
	usleep(1 * 1000000);
	printf("leave %s\n", __FUNCTION__);
	return 0;
}
static int handle_state_conn()
{
	printf("enter %s\n", __FUNCTION__);
	usleep(4 * 1000000);
	printf("leave %s\n", __FUNCTION__);
	return 0;
}
static int handle_state_session_timeout()
{
	printf("enter %s\n", __FUNCTION__);
	usleep(2 * 1000000);
	printf("leave %s\n", __FUNCTION__);
	return 0;
}


state_process stps[] = {
	handle_state_init, 
	handle_state_conn, 
	handle_state_session_timeout
};
static void *st = NULL;

static void recv_signal(int sig)
{
	destroy_state_machine(st);
	exit(0);
}

static int catch_signal()
{
	signal(SIGSEGV, recv_signal);
	signal(SIGINT, recv_signal);
	signal(SIGPIPE, recv_signal);
	signal(SIGTERM, recv_signal);
	return 0;
}

int main(int argc, char **argv)
{
	catch_signal();
	st = init_state_machine(stps, sizeof(stps)/sizeof(stps[0]));
	enqueue_state_machine(st, STATE_INIT);
	usleep(4 * 1000000);
	enqueue_state_machine(st, STATE_CONN);
	usleep(4 * 1000000);
	enqueue_state_machine(st, STATE_SESSIONTIMEOUT);
	while(1)
	{
		usleep(2 * 1000000);
	}
	return 0;
}
