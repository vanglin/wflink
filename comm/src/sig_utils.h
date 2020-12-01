#ifndef __SIG_UITLS__
#define __SIG_UITLS__

#include <pthread.h>
#include "stddef.h"

int get_cmd_value(const char *cmd, char *value,int maxsize);
int start_thread(void*callbak,void *data,void*out);
unsigned int utils_get_ms(void);


typedef pthread_mutex_t sig_mutex_t;
typedef  pthread_cond_t sig_cond_t;

typedef pthread_rwlock_t sig_lock_t;
typedef pthread_rwlockattr_t sig_attr_t;

int sig_rwlock_init(sig_lock_t * rwlock, const sig_attr_t * attr);

int sig_rwlock_destroy(sig_lock_t *rwlock);

int sig_lock_read(sig_lock_t *rwlock);

int sig_lock_rw(sig_lock_t *rwlock);

int sig_unlock_rw(sig_lock_t *rwlock);



int sig_mutex_init(sig_mutex_t* mutex,void*attr);
int sig_mutex_lock(sig_mutex_t*	mutex);
int sig_mutex_unlock(sig_mutex_t*	mutex);
int  sig_mutex_free(sig_mutex_t* mutex);
int sig_mutex_trylock(sig_mutex_t* mutex);

int sig_cond_init(sig_cond_t *cond, void*cond_attr);
int sig_cond_signal(sig_cond_t *cond);
int sig_cond_broadcast(sig_cond_t *cond);int sig_cond_destroy(sig_cond_t *cond);
int sig_cond_wait(sig_cond_t *cond,sig_mutex_t*mutex);
int sig_cond_timedwait(sig_cond_t *cond,sig_mutex_t*mutex ,int ms);
int sig_jiffies_cond_init(sig_cond_t *cond,void*cond_attr);
int sig_jiffies_cond_timedwait(sig_cond_t *cond,sig_mutex_t*mutex ,int ms);


#define SIG_TIMEOUT  30
#define SIG_MISMATCH 31
int sig_post(void*pccb,void*data,int len,int status);
int sig_wait_time(void*pccb,int ms,void*data,int len,int *value);
void seq_free(void*ccb);
void* seq_alloc(void*obj,int *pos);
void*init_sig_cb(int maxs);
void destory_sig_cb(void*obj);
void*sig_get_ccb(void*obj,int id);

/**************list*********************/



#ifdef PJ_LIST_EX
#include "list.h"
#define list_add_tail(_new,head) com_list_insert_before(head,_new)
#define list_del(node) com_list_erase(node)
#define list_empty(node) com_list_empty(node)
#define INIT_LIST_HEAD(node) com_list_init(node)
#define list_move_tail(del,head) com_list_erase(del);com_list_insert_before(head,del)

#else
struct list_head{
        struct list_head *next;
        struct list_head *prev;
        char data[0];
};
static inline void INIT_LIST_HEAD(struct list_head *list)
{
        list->next = list;
        list->prev = list;
}

static inline int list_empty(const struct list_head *head)
{
        return head->next == head;
}
static inline void __list_add(struct list_head *_new,
                              struct list_head *prev,
                              struct list_head *next)
{
        next->prev = _new;
        _new->next = next;
        _new->prev = prev;
        prev->next = _new;
}
static inline void list_add_tail(struct list_head *_new, struct list_head *head)
{
        __list_add(_new, head->prev, head);
}
static inline void __list_del(struct list_head *prev, struct list_head *next)
{
        next->prev = prev;
        prev->next = next;
}

#define LIST_POISON1  ((void *) 0x00100100)
#define LIST_POISON2  ((void *) 0x00200200)
static inline void list_del(struct list_head *entry)
{
        __list_del(entry->prev, entry->next);
        entry->next = (struct list_head*)LIST_POISON1;
        entry->prev = (struct list_head*)LIST_POISON2;
}

static inline void list_move_tail(struct list_head *list,
                                  struct list_head *head)
{
        __list_del(list->prev, list->next);
        list_add_tail(list, head);
}
#endif
static inline void list_add_data(struct list_head*head,void*data)
{
	struct list_head*node= (struct list_head*)((char*)data-offsetof(struct list_head,data));
	list_add_tail(node,head);
}
static inline void list_del_data(void*data)
{
	struct list_head*node= (struct list_head*)((char*)data-offsetof(struct list_head,data));
	list_del(node);
}


#define list_for_each_safe(pos, n, head) \
        for (pos = (head)->next, n = pos->next; pos != (head); \
                pos = n, n = pos->next)

struct list_cache_t
{
		int num;
		int using;
		char *mem_ptr;
		struct list_head free;
		struct list_head used;
};
int init_list_cache(struct list_cache_t*list_cache,int maxs,int cach_size,int (*init_data)(void*data,void*args),void*args);
void*list_cache_alloc(struct list_cache_t*list_cache);
int list_cache_free(struct list_cache_t*list_cache,void*data);
void* list_cache_overlap(struct list_cache_t*list_cache,int (*excute_func)(char*data,void*args),void*args);
int list_cache_destroy(struct list_cache_t*list_cache,int (*destory_data)(char*data,void*args));
int list_cache_using(struct list_cache_t*list_cache);
void comm_list_sort(struct list_head *head,
    int (*cmp)(const struct list_head *, const struct list_head *));
int add_list_sort(struct list_head *head,struct list_head *_new,
    						int (*cmp)(struct list_head *_new, struct list_head *q));
#endif
