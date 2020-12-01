#ifndef __THREAD_QUEUE_H__
#define __THREAD_QUEUE_H__

int add_task_pool(void*thread_pool,char*buf,int len,void*args,int (*proc)(char*buf,int len,char*args));
void destory_thread_pool(void*thread_pool);
void*init_thread_pool(int max_threads);
int process_task_pool(void (*cb_func)(void*user_data),void *user_data,void*thread_pool);

#endif
