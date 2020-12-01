#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include "sig_utils.h"

int get_cmd_value(const char *cmd, char *value,int maxsize)
{
	 int	 ret = -1;
	 FILE	 *fp = NULL;
	 fp = popen(cmd, "r");
	 if(fp)
	 {
	 	if(value)
 		{
			 fgets(value, maxsize, fp);
 		}
		 pclose(fp);
		 ret = 0;
	 } 
	 return ret;
}

 int start_thread(void*callbak,void *data,void*out)
{
    static pthread_t anewthread;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    pthread_create(&anewthread, &attr, callbak, data);
   if(out)
   		*(( pthread_t*)out)=anewthread;
    pthread_attr_destroy(&attr);
    return 0;
}

unsigned int utils_get_ms(void)
{
	 struct timespec	 CurrentTime;
	 clock_gettime( CLOCK_REALTIME, &CurrentTime );
	 return( (unsigned int)	 ((CurrentTime.tv_sec * 1000)+ (CurrentTime.tv_nsec / 1000000)) );
}


/**************************************************************************************************************************************************


                                sig lock

/***************************************************************************************************************************************************/



int sig_mutex_init(sig_mutex_t* mutex,void*attr)
{
	return pthread_mutex_init(mutex, attr);
}

int sig_mutex_lock(sig_mutex_t*	mutex)
{
	return pthread_mutex_lock(mutex);
}

int sig_mutex_unlock(sig_mutex_t*	mutex)
{
	return pthread_mutex_unlock(mutex);
}
int  sig_mutex_free(sig_mutex_t* mutex)
{
	return pthread_mutex_destroy(mutex);
}

int sig_rwlock_init(sig_lock_t * rwlock, const sig_attr_t * attr)
{
	return pthread_rwlock_init(rwlock,attr);
}
int sig_rwlock_destroy(sig_lock_t *rwlock)
{
	return pthread_rwlock_destroy(rwlock);
}
int sig_lock_read(sig_lock_t *rwlock)
{
	return pthread_rwlock_rdlock(rwlock);
}
int sig_lock_rw(sig_lock_t *rwlock)
{
	return pthread_rwlock_wrlock(rwlock);
}
int sig_unlock_rw(sig_lock_t *rwlock)
{
	return pthread_rwlock_unlock(rwlock);
}
int sig_mutex_trylock(sig_mutex_t* mutex)
{
   return pthread_mutex_trylock(mutex);
}
/**************************************************************************************************************************************************


                                sig conthread

/***************************************************************************************************************************************************/

int sig_cond_init(sig_cond_t *cond, void*cond_attr)
{
	return pthread_cond_init(cond, cond_attr);
}

int sig_cond_signal(sig_cond_t *cond)
{
	return pthread_cond_signal(cond);
}

int sig_cond_broadcast(sig_cond_t *cond)
{
	return pthread_cond_broadcast(cond);
}

int sig_cond_destroy(sig_cond_t *cond)
{
	return pthread_cond_destroy(cond);
}

int sig_cond_wait(sig_cond_t *cond,sig_mutex_t*mutex)
{
	return pthread_cond_wait(cond, mutex);
}

int sig_cond_timedwait(sig_cond_t *cond,sig_mutex_t*mutex ,int ms)
{
    struct timespec timeout = {0, 0};   
	int val=0;
    if(!ms)
	{
		return pthread_cond_wait(cond, mutex);
	}
	else
	{
		clock_gettime(CLOCK_REALTIME, &timeout); 
		val=ms/1000;
		if(val)
		{
			timeout.tv_sec = timeout.tv_sec + val;
			ms=ms%1000;
		}
		//else
		{
			timeout.tv_nsec = timeout.tv_nsec +(ms*1000000);
		}
		return pthread_cond_timedwait(cond,mutex, &timeout);
	}
	return 0;
}

int sig_jiffies_cond_init(sig_cond_t *cond,void*cond_attr)
{
	pthread_condattr_t attr;
	int ret = pthread_condattr_init(&attr);
	if (ret != 0) {
		return -1;
	}
	ret = pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
	ret = pthread_cond_init(cond, &attr);
	pthread_condattr_destroy(&attr);
	return ret;
}
int sig_jiffies_cond_timedwait(sig_cond_t *cond,sig_mutex_t*mutex ,int ms)
{
    struct timespec timeout = {0, 0};   
	int val=0;
    if(!ms)
	{
		return pthread_cond_wait(cond, mutex);
	}
	else
	{
		clock_gettime(CLOCK_MONOTONIC, &timeout); 
		val=ms/1000;
		if(val)
		{
			timeout.tv_sec = timeout.tv_sec + val;
			ms=ms%1000;
		}
		//else
		{
			timeout.tv_nsec = timeout.tv_nsec +(ms*1000000);
		}
		return pthread_cond_timedwait(cond,mutex, &timeout);
	}
	return 0;
}



/**************************************************************************************************************************************************


                                sig sync now

/***************************************************************************************************************************************************/

struct signal_res_t
{
	pthread_mutex_t lock;
	pthread_cond_t cond;
	int cbid;
	unsigned int  type :1; // 1 __size used for interger value
	unsigned int  used :2;
	unsigned int status:5;
	int __size;
	char*args;
	char v[0];    
};

struct sync_t
{
	pthread_mutex_t cblock;
	int freepos;
	int max_resource;
	struct signal_res_t ccb[0];
};
void destory_sig_cb(void*obj)
{
	int id=0;
	
	struct signal_res_t *ccb=NULL;
	struct sync_t *sync_ccb=(struct sync_t *)obj;
	pthread_mutex_lock(&(sync_ccb->cblock));
	for(id=0;id<sync_ccb->max_resource;id++)
	{
		ccb=&(sync_ccb->ccb[id]);
		pthread_cond_signal(&ccb->cond);
		ccb=NULL;
	}
	pthread_mutex_unlock(&(sync_ccb->cblock)); 
	free(obj);
}
void*init_sig_cb(int maxs)
{

    int i =0;
	struct signal_res_t *pcb_res=NULL;
	
	struct signal_res_t *pcb_ccb=NULL;
	struct sync_t *sync_ccb=malloc((sizeof(struct signal_res_t)*maxs)+sizeof(struct sync_t));

	if(!sync_ccb)
	{
		return NULL;
	}
	sync_ccb->freepos=0;
	sync_ccb->max_resource=maxs;
	pcb_ccb = sync_ccb->ccb;
	pthread_mutex_init(&(sync_ccb->cblock), NULL);
	for(i=0;i<maxs;i++)
	{
	    pcb_res=&pcb_ccb[i];
		pthread_mutex_init(&pcb_res->lock, NULL);
		pthread_cond_init( &(pcb_res->cond), NULL );  
		
		pcb_res->used=0;
		pcb_res->type=0;
		pcb_res->status=0;
		pcb_res->args=NULL;		
		pcb_res->__size=0;
		pcb_res->cbid=i;
	}
	return sync_ccb;
}

void* seq_alloc(void*obj,int *pos)
{
	struct signal_res_t *ccb=NULL;
    int id=0;
	struct sync_t *sync_ccb=(struct sync_t *)obj;
	pthread_mutex_lock(&(sync_ccb->cblock));
	for(id=sync_ccb->freepos;id<sync_ccb->max_resource;id++)
	{
		ccb=&(sync_ccb->ccb[id]);
		
		if(pthread_mutex_trylock(&ccb->lock))
		{
			ccb=NULL;
			continue;
		}
		if(!ccb->used)
		{
			ccb->used=1;
			sync_ccb->freepos=id+1;
			if(sync_ccb->freepos>=sync_ccb->max_resource)
			{
				sync_ccb->freepos=0;
			}
			pthread_mutex_unlock(&ccb->lock);
			break;
		}		
		pthread_mutex_unlock(&ccb->lock);
		ccb=NULL;
	}
	if(ccb==NULL)
	{
		for(id=0;id<sync_ccb->freepos;id++)
		{
			ccb=&(sync_ccb->ccb[id]);
			
			if(pthread_mutex_trylock(&ccb->lock))
			{
				ccb=NULL;
				continue;
			}
			if(!ccb->used)
			{
				ccb->used=1;
				sync_ccb->freepos=id+1;
				pthread_mutex_unlock(&ccb->lock);
				break;
			}		
			pthread_mutex_unlock(&ccb->lock);
			ccb=NULL;
		}
	}
	pthread_mutex_unlock(&(sync_ccb->cblock));
	if(pos)
	{
		*pos=id;
	}
    return ccb;
}
void seq_free(void*ccb)
{
	struct signal_res_t *pccb=(struct signal_res_t *)ccb;
	if(!pccb)
	{
		return;
	}
	pthread_mutex_lock(&pccb->lock);
	pccb->used=0;
	pccb->type=0;	
	pccb->status=0;
	pccb->args=NULL;
	pccb->__size=0;
	pthread_mutex_unlock(&pccb->lock);
	return;
}
int sig_wait_time(void*pccb,int ms,void*data,int len,int *value)
{
	int res=0;
	int val=0;
	struct timespec timeout = {0, 0};
	struct signal_res_t *ccb=(struct signal_res_t *)pccb;
	pthread_mutex_lock(&ccb->lock);
	ccb->args=data;
	ccb->__size=len;
	ccb->status=0;
	ccb->used++;
	if(ms<=0)
	{
		pthread_cond_wait(&ccb->cond,&ccb->lock);
	}
	else
	{
		clock_gettime(CLOCK_REALTIME, &timeout); 
		val=ms/1000;
		if(val)
			timeout.tv_sec = timeout.tv_sec + val;
		else
			timeout.tv_nsec = timeout.tv_nsec +(ms*1000000);
		res=pthread_cond_timedwait(&ccb->cond,&ccb->lock, &timeout);
	}
	ccb->used--;
	if(res == ETIMEDOUT)
	{
		res =-1;
	}
	else
	{
		res=ccb->status;
	}
	
	if(value)
		*value=ccb->__size;

	ccb->args=NULL;
	ccb->__size=0;
	ccb->status=0;
	
	pthread_mutex_unlock(&ccb->lock);	
	return res;

}

int sig_post(void*pccb,void*data,int len,int status)
{
	struct signal_res_t *ccb=(struct signal_res_t *)pccb;
	pthread_mutex_lock(&ccb->lock);
	if(ccb->used<=1)
	{
		pthread_mutex_unlock(&ccb->lock);	
		return -1;
	}
	if(!data)
	{
		ccb->__size=len;
		ccb->type =1;
	}
	else
	{
		if(!ccb->__size)
	 	{
			ccb->args=data;
			ccb->__size=len;	 		
	 	}
		else
		{
			if(ccb->args)
			{
				if(len==0 || len >ccb->__size)
					len=ccb->__size;
				memcpy(ccb->args,data,len);
			}
		}
		ccb->type =0;
	}
	ccb->status = status;
	pthread_cond_signal(&ccb->cond);
    pthread_mutex_unlock(&ccb->lock);	
	return 0;
}
void*sig_get_ccb(void*obj,int id)
{
	struct signal_res_t *ccb=NULL;
	struct sync_t *sync_ccb=(struct sync_t *)obj;
	pthread_mutex_lock(&(sync_ccb->cblock));
	if(id<sync_ccb->max_resource)
	{
		ccb=&(sync_ccb->ccb[id]);
	}
	pthread_mutex_unlock(&(sync_ccb->cblock));
	return (void*)ccb;
}


/************************************************************************************************

#include "list.h"


*************************************************************************************************/

int print_list(struct list_head*head)
{
        struct list_head*pos=NULL;
        struct list_head*posn=NULL;
        if(list_empty(head))
        {
                return -1;
        }
        list_for_each_safe(pos, posn, head)
        {
              printf("[%s]=%p\n",__FUNCTION__,pos);
        }
		return 0;
}

int init_list_cache(struct list_cache_t*list_cache,int maxs,int cach_size,int (*init_data)(void*data,void*args),void*args)
{
        int i=0;
        struct list_head *node=NULL;
        char *head=malloc((cach_size+sizeof(struct list_head))*maxs);
        if(!head)
        {
                return -1;
        }
        list_cache->mem_ptr=head;

        INIT_LIST_HEAD(((struct list_head*)(&(list_cache->free))));
        INIT_LIST_HEAD(((struct list_head*)(&(list_cache->used))));

        for(i=0;i<maxs;i++)
        {
           node = (struct list_head *)(head + i*(cach_size+sizeof(struct list_head)));
           list_add_tail(((struct list_head*)node),((struct list_head*)&(list_cache->free)));
           if(init_data)
		   	   init_data(node->data,args);
        }
        list_cache->num=maxs;
        list_cache->using=0;
        return 0;
}
void*list_cache_alloc(struct list_cache_t*list_cache)
{
        struct list_head  *node=&(list_cache->free);
        if(list_empty(node))
        {
                return NULL;
        }
        node=node->next;
        list_move_tail(((struct list_head*)node),((struct list_head*)(&(list_cache->used))));
        list_cache->using++;

        return node->data;
}

int list_cache_free(struct list_cache_t*list_cache,void*data)
{
        struct list_head*node=NULL;
        node= (struct list_head*)((char*)data-offsetof(struct list_head,data));
        list_move_tail(((struct list_head*)node),((struct list_head*)(&(list_cache->free))));
        list_cache->using--;

        return 0;
}

void list_cache_used(struct list_cache_t*list_cache,void*data)
{
	struct list_head*node=(struct list_head*)((char*)data-offsetof(struct list_head,data));

	list_add_tail(node,((struct list_head*)(&(list_cache->used))));
	list_cache->using++;	
    return ;
}
void list_cache_restore(struct list_cache_t*list_cache,void*data)
{
	struct list_head*node=(struct list_head*)((char*)data-offsetof(struct list_head,data));

	list_add_tail(node,((struct list_head*)(&(list_cache->free))));
	list_cache->using--;	
    return ;
}

void*list_cache_get(struct list_head  *node)
{
	if(!node||list_empty(node))
	{
			return NULL;
	}
	node=node->next;
	list_del(node);
	return node->data;
}
void* list_cache_overlap(struct list_cache_t*list_cache,int (*excute_func)(char*data,void*args),void*args)
{
        int res =0;
        if(excute_func)
        {
                struct list_head*pos=NULL;
                struct list_head*posn=NULL;
                if(list_empty((struct list_head*)(&(list_cache->used))))
                {
                        return NULL;
                }
                list_for_each_safe(pos, posn, (struct list_head*)(&(list_cache->used)))
                {
                        if(0==(res=excute_func(((struct list_head*)pos)->data,args)))
                        {
                                list_move_tail((struct list_head*)pos,(struct list_head*)(&(list_cache->free)));
                                list_cache->using--;
                        }
                        else if (res==1)
                        {
                                return ((struct list_head*)pos)->data;
                        }
                }
        }
        return NULL;
}
int list_cache_destroy(struct list_cache_t*list_cache,int (*destory_data)(char*data,void*args))
{

    list_cache_overlap(list_cache,destory_data,NULL);
        if(list_cache->mem_ptr)
        {
                free(list_cache->mem_ptr);
        }
        list_cache->mem_ptr=NULL;
        list_cache->using=0;
        return 0;
}
int list_cache_using(struct list_cache_t*list_cache)
{
	return list_cache->using;
}
void comm_list_sort(struct list_head *head,
    int (*cmp)(const struct list_head *, const struct list_head *))
{
    struct list_head  *q, *prev, *next;

    q = head->next;

    if (q == head->prev) {
        return;
    }

    for (q = q->next; q != head; q = next) {

        prev = q->prev;
        next = q->next;
        list_del(q);

        do {
            if (cmp(prev, q) <= 0) {
                break;
            }

            prev = prev->prev;

        } while (prev != head);

        q->next=prev->next;
        prev->next->prev=q;
        prev->next=q;
        q->prev=prev;
    
    }
}
int add_list_sort(struct list_head *head,struct list_head *_new,
    						int (*cmp)(struct list_head *_new, struct list_head *q))
{
	struct list_head  *q=NULL;
	struct list_head  *last=NULL;
	int res=0;
	q = head->next;
	if (q != head&&cmp) 
	{
		for (q = q; q != head; q = q->next) {
			if ((res=cmp(_new, q)) <= 0) {
				break;
			}
			last=q;
		}
	}
	if(!last)
	{
		last=head;
	}
	q=last->next;
	last->next=_new;
	_new->prev=last;
	_new->next=q;
	q->prev=_new;	
	return res;
}
