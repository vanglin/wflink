#ifndef __DATE_LIST_H__
#define __DATE_LIST_H__
#include "sig_utils.h"
/*
base          start         end
|			  | 			|	
start > base; no used; so add in date->left

start         base         end
|			  | 			|	
start < base< end;  using; so add in date->used

start         end         base
|			  | 			|	

end <base; maybe had been used; if cycle,and need to + interval;else ignor

offset is starttime; maybe it is starttime next period;

*/
int date_lock();
int date_unlock();

/*must used for init lock*/
int date_init_lock();

/*get now time using seconds*/
unsigned long get_now_seconds(unsigned long last_time);

/*mktime*/
long  transfer_time(char*datastr);

int delete_group(struct list_head *head);
/*
    group add date list header; data ptr map a group;and this group callback ,timer 
*/
struct list_head *Group_add(struct list_head *head,void*ptr,struct list_head *date_table,
								void*htimer,int (*cb_func)(void*refptr,int start_stop,void*args));
/*
    search for date from date_table;add this date point to group->date 
    change date->refptr point to refptr
*/
int Group_add_date(void*group,int refid,void*refptr);
/*
    excute func callback; refptr is from seaching group->date
*/
int Group_get_date_time(void *group,int (*func)(void*refptr,void*args,void*out,int len),void*args,void*out,int len);
/*
   get date->args date->refptr by datetime
*/
int get_date_args_by_time(void*datetime,void**args,void**refptr);

/*
  1. exucte rule_append for Group_get_date_time
  2. start timer call back is set by Group_add
*/
int start_group_date(void*group,void*htimer,long base,
							int (*rule_append)(void*refptr,void*args,void*out,int len),void*args,void*out,int len);


/*set_date_relation
set call back for date
and start timer for date
head ; list for date;
refid; is ref dataid,index
refptr; point for data;
args; params for cb_func
base;now time

*/
int set_date_relation(struct list_head *head,int refid,void*refptr,void*htimer,long base,int (*cb_func)(void*refptr,int start_stop,void*args),void*args);
struct list_head* add_date(int refid,int circletype,int interval,int enable,struct list_head *head);
struct list_head*date_add_time(long base,void*pdate,long starttime,long endtime);
int delete_date(int refid,struct list_head *head);
#endif

