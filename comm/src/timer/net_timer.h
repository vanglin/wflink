#ifndef __NET_TIMER__H_
#define __NET_TIMER__H_
#ifndef __PRESION_TIMER__
#include "sig_utils.h"
#endif
void* timer_init(int epfd,int presion,int (*process_func)(void (*cb_func)(void*user_data),void *user_data,void*thread_pool),void*thread_pool);
void timer_stop(void*htimer);
long timer_add(void* htimer,unsigned int tm_ms,unsigned int interval,
					void (*timer_cb_func)(void *user_data),  void *user_data);
int timer_del(void* htimer, long timer_id);
long timer_replace(void* htimer,long timer_id,unsigned int tm_ms,unsigned int interval,
					void (*timer_cb_func)(void *user_data),  void *user_data);

void*timer_get_params(void* htimer, long timer_id);

#endif
