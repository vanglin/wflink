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
#include "sig_utils.h"

#define MAX_STATE_TYPE 16

struct statemachine_t
{
	sig_mutex_t lock;
	sig_cond_t cond;
	struct list_head queue;
	pthread_t pid;
	int exit;
	state_type_t state;
	state_process processes[MAX_STATE_TYPE];
};

static void *st_pthread(void *state_machine)
{
	struct statemachine_t *st = (struct statemachine_t *)state_machine;
	int b_exit = 0;
	state_type_t state = 0;
	struct list_head *task = NULL;
	struct list_head *pos, *n;
	state_process process = NULL;
	
	while(1)
	{
		sig_mutex_lock(&st->lock);
		sig_cond_timedwait(&st->cond, &st->lock, 500);
		b_exit = st->exit;
		if(b_exit)
		{
			sig_mutex_unlock(&st->lock);
			break;
		}
		if(list_empty(&st->queue))
		{
			sig_mutex_unlock(&st->lock);
			continue;
		}
		task = st->queue.next;
		list_del(task);
		state = *((state_type_t *)task->data);
		if(state < MAX_STATE_TYPE)
		{
			process = st->processes[state];
			st->state = state;
		}
		else
		{
			process = NULL;
		}
		sig_mutex_unlock(&st->lock);
		if(process)process();
	}
	list_for_each_safe(pos,n,&st->queue)
	{
		list_del(pos);
		free(pos);
	}
	sig_mutex_free(&st->lock);
	sig_cond_destroy(&st->cond);
	return NULL;
}

void *init_state_machine(state_process *processes, int state_num)
{
	struct statemachine_t *st = (struct statemachine_t *)malloc(sizeof(struct statemachine_t));
	int i = 0;
	if(!st)
		return NULL;
	memset(st, 0, sizeof(*st));
	sig_mutex_init(&st->lock, NULL);
	sig_cond_init(&st->cond, NULL);
	INIT_LIST_HEAD(&st->queue);
	for(i = 0; i < state_num; i++)
	{
		if(processes[i])st->processes[i] = processes[i];
	}
	start_thread(st_pthread, (void *)st, (void *)&st->pid);
	return (void *)st;
}

int enqueue_state_machine(void *state_machine, state_type_t state)
{
	struct statemachine_t *st = (struct statemachine_t *)state_machine;
	struct list_head *task = NULL;
	if(!st)
		return -1;
	task = (struct list_head *)malloc(sizeof(struct list_head) + sizeof(state_type_t));
	if(!task)
		return -1;
	memcpy(task->data, &state, sizeof(state_type_t));
	sig_mutex_lock(&st->lock);
	list_add_tail(task, &st->queue);
	sig_mutex_unlock(&st->lock);
	sig_cond_signal(&st->cond);
	return 0;
}

void destroy_state_machine(void *state_machine)
{
	struct statemachine_t *st = (struct statemachine_t *)state_machine;
	struct list_head *pos, *n;
	if(!st)
		return;
	if(st->pid > 0)
	{
		sig_mutex_lock(&st->lock);
		st->exit = 1;
		sig_mutex_unlock(&st->lock);
	}
	else
	{
		list_for_each_safe(pos,n,&st->queue)
		{
			list_del(pos);
			free(pos);
		}
		sig_mutex_free(&st->lock);
		sig_cond_destroy(&st->cond);
	}
	return;
}

int get_current_state(void *state_machine)
{
	struct statemachine_t *st = (struct statemachine_t *)state_machine;
	if(!st)
		return -1;
	int ret = 0;
	sig_mutex_lock(&st->lock);
	ret = (int)st->state;
	sig_mutex_unlock(&st->lock);
	return ret;
}
