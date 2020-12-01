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
#include "thread_queue.h"
#include "sig_utils.h"
#define err_log(fmt...) \
do{\
	printf("%s:%s [%d] ",__FILE__,__FUNCTION__, __LINE__);\
	printf(fmt);\
}while(0)

struct frame_t
{
	char *args;
	int (*proc)(char*buf,int len,char*args);
	int len;
	char buf[0];
};

struct threadpool_t
{
	sig_mutex_t lock;
	sig_cond_t cond;	
	int stop;
	int max_threads;
	struct list_head task;	
};
static void*thread_queue(void*unused);

void*init_thread_pool(int max_threads)
{
	int i=0;
	struct threadpool_t*pool=malloc(sizeof(struct threadpool_t));
	if(!pool)
	{
		return NULL;
	}
	sig_mutex_init(&(pool->lock),NULL);
	sig_cond_init(&(pool->cond),NULL);
	pool->stop=0;
	pool->max_threads=max_threads;
	INIT_LIST_HEAD(&(pool->task));
	
	for(i=0;i<max_threads;i++)
	{
		start_thread(thread_queue,pool,NULL);
	}
	return pool;
}

void destory_thread_pool(void*thread_pool)
{
	struct threadpool_t*pool=(struct threadpool_t*)thread_pool;
	if(!pool)
	{
		return ;
	}
	sig_mutex_lock(&(pool->lock));
	pool->stop=1;
	sig_cond_broadcast(&pool->cond);
	sig_mutex_unlock(&(pool->lock));
	usleep(500);
	free(pool);
}
int add_task_pool(void*thread_pool,char*buf,int len,void*args,int (*proc)(char*buf,int len,char*args))
{
	struct frame_t*frame=NULL;
	struct list_head *pos=NULL;
	struct threadpool_t*pool=(struct threadpool_t*)thread_pool;
	if(!pool)
	{
		return -1;
	}
	pos=(struct list_head*)malloc(len+sizeof(struct frame_t)+sizeof(struct list_head));
	if(!pos)
	{
		return -1;
	}		
	INIT_LIST_HEAD(pos);
	frame=(struct frame_t*)pos->data;
	frame->args=args;
	frame->len=len;
	frame->proc=proc;
	if(buf)
	{
		memcpy(frame->buf,buf,len);
	}
	sig_mutex_lock(&(pool->lock));
	list_add_tail(pos,&(pool->task));
	sig_mutex_unlock(&(pool->lock));	
	sig_cond_signal(&(pool->cond));
	return 0;
}
static void*thread_queue(void*unused)
{
	int sqid=-1;
	struct list_head *task;
	struct threadpool_t*pool=(struct threadpool_t*)unused;	
	if(!pool)
	{
		return NULL;
	}
	for(;;)
	{
		sig_mutex_lock(&(pool->lock));
		if(pool->stop)
		{
			sig_mutex_unlock(&(pool->lock));
			break;
		}	
		if(list_empty(&(pool->task)))
		{
			sig_cond_wait(&(pool->cond),&(pool->lock));
			if(pool->stop)
			{
				sig_mutex_unlock(&(pool->lock));
				break;
			}
			if(list_empty(&(pool->task)))
			{
				sig_mutex_unlock(&(pool->lock));
				continue;
			}
		}
		task=pool->task.next;
		list_del(task);
		sig_mutex_unlock(&(pool->lock));
		struct frame_t*frame=(struct frame_t *)task->data;
		if(frame->proc)
		{
			frame->proc(frame->buf,frame->len,frame->args);
		}
		free((void*)task);
	}
	//
	return NULL;
}


struct ptr_func_t
{
	void (*cb_func)(void *user_data);
};


static int ptr_thread_proc(char*buf,int len,char*args)
{
	struct ptr_func_t *func=(struct ptr_func_t *)buf;
	if(func->cb_func)
	{
		func->cb_func(args);
	}
	return 0;
}

int process_task_pool(void (*cb_func)(void*user_data),void *user_data,void*thread_pool)
{
	int res=0;
	if(thread_pool)
	{
		struct ptr_func_t stfunc;
		stfunc.cb_func=cb_func;
		res=add_task_pool(thread_pool,(char*)&stfunc,sizeof(struct ptr_func_t),user_data,ptr_thread_proc);
	}
	else
	{
		if(cb_func)
		{
			cb_func(user_data);
		}
	}
	return res;
}



