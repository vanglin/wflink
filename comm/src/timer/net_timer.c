#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <linux/types.h>
#include <sys/epoll.h>
#include <sys/wait.h>
#include "stddef.h"
#include <fcntl.h>
#include "poll.h"
#include "rbtree.h"
#include "net_timer.h"

typedef struct rb_root 	 heap_t;

typedef struct{
     struct rb_node node;  
	 unsigned long interval;
	 int cycle;
	 long timer_id;
	 void *user_data;
	 void (*timer_cb_func)(void *user_data);
}timer_node_t;

struct dev_timer_heap{
	sig_mutex_t		  lock; 			  //lock
	union {
	 int				 pipfd[2];
	 sig_cond_t 		 cond; 
	}notify;
	heap_t 			 heap;
	int				 start;
	void			 *thread_pool;
	unsigned long	 base;
	unsigned long	 elapse;
	int				 presion;
	int				 epfd;	//0 is cond,>1 is epoll,<0 is poll		
	int				 (*process_func)(void (*cb_func)(void*user_data),void *user_data,void*thread_pool); 
	int 			 (*delay_func)(int presion,int last_period,struct dev_timer_heap*ptimer);
};
unsigned long get_current_ms(unsigned long last_time)
{
#ifdef __PRESION_TIMER__
	unsigned long tmp=0;
	struct timeval tv;
	gettimeofday(&tv,NULL);
	tmp = tv.tv_sec*1000+tv.tv_usec/1000;

	return (unsigned long)(tmp-last_time);
#else
	return (utils_get_ms()-last_time);
#endif
}


int node_insert(struct rb_root *root, timer_node_t *data)  
{  
    struct rb_node **tmp = &(root->rb_node), *parent = NULL;  
    /* Figure out where to put new node */  
    while (*tmp) {  
	    timer_node_t *node = container_of(*tmp,timer_node_t, node);  
	  
	    parent = *tmp;  
	    if (data->interval< node->interval)  
	        tmp = &((*tmp)->rb_left);  
	    else if (data->interval >= node->interval)  
	        tmp = &((*tmp)->rb_right);  
	    else   
	        return -1;  
    }  
      
    /* Add new node and rebalance tree. */  
    rb_link_node(&data->node, parent, tmp);  
    rb_insert_color(&data->node, root);  
      
    return 0;  
}  

static int cond_delay_func(int presion,int last_period,struct dev_timer_heap*ptimer)
{
	int res=0;
	if(!last_period)
	{
		last_period=presion;
	}
	sig_mutex_lock(&(ptimer->lock));
	
	res=sig_cond_timedwait(&(ptimer->notify.cond),&(ptimer->lock),last_period);
	if(ETIMEDOUT==res)
	{
		res=last_period;
		ptimer->elapse+=res;
	}
	else
	{
		res=(int)get_current_ms(ptimer->base);
		ptimer->elapse=res;
	}
	
	sig_mutex_unlock(&(ptimer->lock));
	return res;
}

static int poll_delay_func(int presion,int last_period,struct dev_timer_heap*ptimer)
{
	int res=0;
	int fd=-1;
	int base=0;
	if(!last_period)
	{
		last_period=presion;
	}
	sig_mutex_lock(&(ptimer->lock));
	fd=ptimer->notify.pipfd[0];
	base=ptimer->base;
	sig_mutex_unlock(&(ptimer->lock));
	struct pollfd pfds[1]; 
	char buf[128];
	do{
	    pfds[0].fd = fd;  
	    pfds[0].events = POLLIN; 
		res=poll(pfds,1,last_period);	
		if(res==0)
		{
			res=last_period;
			ptimer->elapse+=res;
		}
		else
		{
			res=read(fd,buf,sizeof(buf));
			if(res>0)
			{
				res=(int)get_current_ms(base);
				ptimer->elapse=res;
			}
		}	
	}while(0);  
	return res;
}
static int interrupt_notify(struct dev_timer_heap* ptimer)
{
	if(ptimer->epfd==0)
	{
		return sig_cond_signal(&(ptimer->notify.cond));
	}
	else
	{
		return write(ptimer->notify.pipfd[1],"notify",6);
	}
	return 0;
}
static timer_node_t	 * timer_node_search(struct dev_timer_heap *ptimer,timer_node_t*(*cmp_func)(timer_node_t *timer_node,long* val),long* val)// ms
{
	int res=1;
	timer_node_t	 *timer_node = NULL;
	struct rb_node		*node = NULL;
	timer_node_t	 *res_node = NULL;

	if (node = rb_first(&ptimer->heap))
	{
		for(node = node; node;)
		{
			timer_node = rb_entry(node, timer_node_t, node);
			node = rb_next(node);			
			rb_erase(&timer_node->node, &ptimer->heap);
			if(cmp_func)
			{
				res_node=cmp_func(timer_node,val);
				if(res_node)
				{
					break;
				}
				node_insert(&ptimer->heap, timer_node);
			}
			else
			{
				free(timer_node);
			}
		}
	}
	return res_node;
				
}
void timer_destory(struct dev_timer_heap *ptimer)
{
	if(ptimer)
	{
		
		timer_node_search(ptimer,NULL,NULL);
		sig_mutex_free(&(ptimer->lock));
		if(ptimer->epfd)
		{
			close(ptimer->notify.pipfd[0]);
			close(ptimer->notify.pipfd[1]);
		}
		free(ptimer);
		ptimer = NULL;
	}
	
}
void print_rbtree(struct rb_root *tree)  
{  
    struct rb_node *node;  
   printf("print_rbtree:\n");    
    for (node = rb_first(tree); node; node = rb_next(node))  
          printf("%p", rb_entry(node,timer_node_t, node));  
      
    printf("\n");  
}  


static int timer_process_do(void*unused)// ms
{
	struct rb_node		*node = NULL;
	timer_node_t    *data_node=NULL;
	//int now=0;
	int last_period=0;
	struct dev_timer_heap*ptimer=(struct dev_timer_heap*)unused;
	if(!ptimer)
	{
		return -1;
	}	
	struct rb_root *root=&ptimer->heap;
	int presion=ptimer->presion;
	void *thread_pool=ptimer->thread_pool;	
	int (*process_func)(void (*cb_func)(void*user_data),void *user_data,void*thread_pool)=ptimer->process_func;
	int (*delay_func)(int presion,int last_period,struct dev_timer_heap*ptimer)=ptimer->delay_func;
	//ptimer->base=get_current_ms(0);	

	if(!delay_func)
	{
		goto end;
	}
	int res=0;
	for(;;)
	{
		res=delay_func(presion,last_period,ptimer);
		//now+=res;
		//printf("now=%d,presion=%d;last_period=%d;res===%d\n",now,presion,last_period,res);

		sig_mutex_lock(&(ptimer->lock));
		if(!ptimer->start)
		{
			sig_mutex_unlock(&(ptimer->lock));			
			break;
		}
		root=&ptimer->heap;
		if (node = rb_first(root))
		{
			last_period=0;
			for(node = node; node;node=node)
			{
				data_node = rb_entry(node,timer_node_t, node);
				if(data_node->interval > ptimer->elapse)
				{
					last_period=data_node->interval-ptimer->elapse;
					break;
				}
				node = rb_next(node);			
				rb_erase(&data_node->node, root);
				
				if(process_func)
				{
					process_func(data_node->timer_cb_func,data_node->user_data,thread_pool);
				}
				else if(data_node->timer_cb_func)
				{
					data_node->timer_cb_func(data_node->user_data);
				}
				if(data_node->cycle)
				{
					data_node->interval=ptimer->elapse+data_node->cycle;
					node_insert(root,data_node);
				}
				else
				{
					free(data_node);
				}
			}
			
		}
		else
		{
			ptimer->base=get_current_ms(0);
			last_period=0;
			ptimer->elapse=0;
		}
		sig_mutex_unlock(&(ptimer->lock));

	}
end:
	timer_destory(ptimer);
        return 0;				
}

void* timer_init(int epfd,int presion,int (*process_func)(void (*cb_func)(void*user_data),void *user_data,void*thread_pool),void*thread_pool)
{
    struct dev_timer_heap *ptimer=( struct dev_timer_heap *)malloc(sizeof(struct dev_timer_heap));
	if(!ptimer)
	{
		return NULL;
	}
	memset(ptimer,0,sizeof(struct dev_timer_heap));
    if(sig_mutex_init(&(ptimer->lock), NULL) == -1)
    {
        return;
    }
	
	ptimer->heap			= RB_ROOT;
	ptimer->presion = presion;
	ptimer->start			= 1;
	ptimer->base			= get_current_ms(0);
	ptimer->process_func	= process_func;
	ptimer->thread_pool     = thread_pool;
	ptimer->epfd             = epfd;
	if(epfd==0)
	{
		sig_cond_init(&(ptimer->notify.cond),NULL);
		ptimer->delay_func=cond_delay_func;
	}	
	else
	{
		if(pipe(ptimer->notify.pipfd))
		{
			free(ptimer);
			return NULL;
		}
		if(epfd<0)
		{
			ptimer->delay_func=poll_delay_func;
		}
		else
		{
			ptimer->delay_func=poll_delay_func;
		}
	}
	start_thread(timer_process_do,ptimer,NULL);
	return (void*)ptimer;
}

void timer_stop(void*htimer)
{
	struct dev_timer_heap *ptimer=(struct dev_timer_heap *)htimer;
	sig_mutex_lock(&(ptimer->lock));
	ptimer->start=0;
	interrupt_notify(ptimer);
	sig_mutex_unlock(&(ptimer->lock));
	return;
}
long timer_add(void* htimer,unsigned int tm_ms,unsigned int interval,
					void (*timer_cb_func)(void *user_data),  void *user_data)
{
	long 			ret = -1;
	timer_node_t *pnode = NULL;
	struct dev_timer_heap* ptimer=(struct dev_timer_heap*)htimer;
	if(!ptimer)
	{
		return -1;
	}

	pnode = (timer_node_t*)malloc(sizeof(timer_node_t));
	if(!pnode)
	{
		goto end;
	}
	memset(pnode,0,sizeof(timer_node_t));
	pnode->cycle= interval;
	pnode->timer_cb_func	 = timer_cb_func;
	pnode->user_data	 = user_data;
	sig_mutex_lock(&(ptimer->lock));
	pnode->timer_id =(long)pnode;
	if(tm_ms == 0)
	{
		tm_ms=interval;
	}
	pnode->interval = (int)get_current_ms(ptimer->base)+tm_ms;
	node_insert(&ptimer->heap, pnode);
	ret = pnode->timer_id;
	interrupt_notify(ptimer);
	sig_mutex_unlock(&(ptimer->lock));
end:

	return ret;
}


static timer_node_t *del_func_cmp(timer_node_t *timer_node,long* val)
{
	long timer_id=0;
	if(!val||!timer_node)
	{
		return NULL;
	}
    timer_id = *val;
    if(timer_node->timer_id == timer_id)
    {
		return timer_node;
    }	
	return NULL;
}

int timer_del(void* htimer, long timer_id)
{	
	struct dev_timer_heap*ptimer=(struct dev_timer_heap *)htimer;
	if(!ptimer)
	{
		return -1;
	}	
    sig_mutex_lock(&(ptimer->lock));
	timer_node_t*res_node=timer_node_search(ptimer,del_func_cmp,&timer_id);
	if(res_node)
	{
		free(res_node);
	}
    sig_mutex_unlock(&(ptimer->lock));
	return 0;
}

long timer_replace(void* htimer,long timer_id,unsigned int tm_ms,unsigned int interval,
					void (*timer_cb_func)(void *user_data),  void *user_data)
{
	struct dev_timer_heap*ptimer=(struct dev_timer_heap *)htimer;
	if(!ptimer)
	{
		return -1;
	}	
	if(timer_id==-1)
	{
		timer_id=timer_add(htimer,tm_ms,interval,timer_cb_func,user_data);
	}
	else
	{
		sig_mutex_lock(&(ptimer->lock));
		timer_node_t*pnode=timer_node_search(ptimer,del_func_cmp,&timer_id);
		if(pnode)
		{
			pnode->cycle= interval;
			pnode->timer_cb_func	 = timer_cb_func;
			pnode->user_data	 = user_data;
			pnode->interval = (int)get_current_ms(ptimer->base)+tm_ms;
			
			node_insert(&ptimer->heap, pnode);
			interrupt_notify(ptimer);
		}
		sig_mutex_unlock(&(ptimer->lock));
	}
	return timer_id;
}
void*timer_get_params(void* htimer, long timer_id)
{	
	void*ptr=NULL;
	struct dev_timer_heap*ptimer=(struct dev_timer_heap *)htimer;
	if(!ptimer)
	{
		return ptr;
	}	
    sig_mutex_lock(&(ptimer->lock));
	timer_node_t*res_node=timer_node_search(ptimer,del_func_cmp,&timer_id);
	if(res_node)
	{
		ptr=res_node->user_data;
	}
    sig_mutex_unlock(&(ptimer->lock));
	return ptr;
}

#if 0
void test_cb(void *user_data)
{
	printf("=test_cb====%p==%ld\n",user_data,get_current_ms(0));
}
void test_cb2(void *user_data)
{
	printf("=test_cb2====%p==%ld\n",user_data,get_current_ms(0));
}

int main()
{
	char *ptr="hello,work";
	void*ptimer=timer_init(0,10,NULL,NULL);
	long id=timer_add(ptimer,20,1000,test_cb,ptr);
	printf("%ld,id=%ld;;==%ld\n",ptimer,id,get_current_ms(0));

	long id2=timer_add(ptimer,30,1000,test_cb2,ptr);

	printf("%ld,id=%ld;;==%ld\n",id2-ptimer,id2,get_current_ms(0));
	sleep(5);
	return id;
}
#endif
