#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <dlfcn.h>
#include <time.h>
#include "net_timer.h"
#include "datelist.h"
struct date_ptr_t
{
	char *ptr;
};


struct list_head * table_list_add(struct list_head *head,char*src,int len)
{

     struct list_head *node=(struct list_head*)malloc(sizeof(struct list_head)+len);
	if(!node)
 	{
 		return NULL;
 	}
	memcpy(node->data,src,len);
	list_add_tail(node,head);
	return node;
}
struct list_head * table_list_add_sort(struct list_head *head,char*src,int len,
													int (*cmp)(struct list_head *_new, struct list_head *q))
{
	int res=0;
    struct list_head *node=(struct list_head*)malloc(sizeof(struct list_head)+len);
	if(!node)
 	{
 		return NULL;
 	}
	memcpy(node->data,src,len);	
	res=add_list_sort(head,node,cmp);
	return node;
}


int table_list_free(struct list_head *head,int freed)
{
    struct list_head*pos=NULL;
    struct list_head*posn=NULL;
    if(list_empty(head))
    {
            return -1;
    }
    list_for_each_safe(pos, posn, head)
    {
       list_del(pos);
	    if(freed)
	   	{
	   		free(pos);
	   	}
    }
	return 0;
}

struct list_head *list_search_do(struct list_head *head,int (*func)(char*task,void *args,char *param),void*args,char*param)
{
	int res=0;
	char *task=NULL;
	struct list_head*pos=NULL;
	struct list_head*posn=NULL;
	if(list_empty(head))
	{
			return NULL;
	}
	list_for_each_safe(pos, posn, head)
	{
		task=pos->data;
		if(func)
		{
		    res=func(task,args,param);
		    if(res==1)
		   	{
		   		return pos;
		   	}
			else if(res==2)
			{
				list_del(pos);
				free(pos);
			}
		}
	}
    return NULL;
}


/*************************************************************************************************************





**************************************************************************************************************/
static sig_mutex_t datelock;
int date_lock()
{
	return sig_mutex_lock(&(datelock)); 
}
int date_unlock()
{
	return sig_mutex_unlock(&(datelock)); 
}
int date_init_lock()
{
	return sig_mutex_init(&(datelock),NULL); 
}

enum
{
    enm_date_none,
	enm_date_hour,
	enm_date_day,
	enm_date_week,
	enm_date_mounth,
	enm_date_year,
};
/*
     header ------|______________ |
				  |header 		  |
				  |struct Date_t  | 			  struct Date_time_t	  struct Date_time_t
				  | 			  | 			 |______________ |		  |______________ | 
				  | 		  date|------------->|header		 |------->|header		  | 
				  | 			  | 			 |				 |		  | 			  | 
				  | 		  left|------------->|used_left 	 |	  |-->|used_left	  |
				  | 			  | 			 |______________ |	  |   |______________ |
				  | 		  used|-----------------------------------|
				  |_____________  |

*/
struct Date_t
{
	int refid;
	int circletype;
	int interval;
	int enable;	
	long timeid;
	void *htimer;
	void *refptr;
	void*args;	
	void *group;
	int (*cb_func)(void*refptr,int start_stop,void*args);
	struct list_head date;//in real contact: date=used+left; point to struct Date_time_t header
	struct list_head used; // point to struct Date_time_t .used_left
	struct list_head left; // point to struct Date_time_t .used_left
};
struct Date_time_t
{
	struct Date_t *date;
	long starttime;
	long endtime;
	long startoffset;
	struct list_head used_left; // inserted in struct Date_t; used or left field; only a var here ;not list head
};
static int delete_group_datetime_timer(void*group,struct Date_time_t*pstdatetime);

static struct Date_time_t*get_date_time_ptr(struct list_head*head)
{
	return ((struct Date_time_t*)((char*)head-offsetof(struct Date_time_t,used_left)));
}

unsigned long get_now_seconds(unsigned long last_time)
{
  time_t rawtime;
  time( &rawtime );
  return (rawtime-last_time);
}

long  transfer_time(char*datastr)
{
	struct tm struct_date;
	if(datastr&&strptime(datastr,"%F %X",&struct_date))
	{
	  return mktime(&struct_date);
	}
	return 0;
}

static int divid_result(int input,int inidiv,int *res)
{
	int remainder=0;
	int result=0;
	if(!inidiv)
	{
		if(res)
		{
			*res=0;
		}
		return 0;
	}
	result=input/inidiv;
	remainder=input%inidiv;
	if(res)
	{
		*res=result;
	}
	return remainder;
}
static long transfer_period_time(long tm,int type,int counts)
{
	int res=0;
	int days=0;
	struct tm now_time;  
    if(type==enm_date_week)
	{
		tm+=(7*24*60*60*counts);
		return tm;
	}
	
	localtime_r(&tm, &now_time);	
    if(type==enm_date_hour) 
	{
		now_time.tm_hour+=counts;
		now_time.tm_hour=divid_result(now_time.tm_hour,24,&res);
		if(res)
		{
			type=enm_date_day;
			counts=res;
		}
	}
    if(type==enm_date_day) 
	{
 	 	now_time.tm_mday+=counts;
		if(now_time.tm_mon==2)
		{
			days=28;
			if(!(now_time.tm_year%400)||!(now_time.tm_year%4))
			{
				days=29;
			}
		}
		else if(now_time.tm_mon==4
			    ||now_time.tm_mon==6
			    ||now_time.tm_mon==9
			    ||now_time.tm_mon==11)
		{
			days=30;
		}
		else
		{
			days=31;
		}					
		now_time.tm_mday=divid_result(now_time.tm_mday,days,&res);	
		if(res)
		{
			type=enm_date_mounth;
			counts=res;
		}		
	}
    if(type==enm_date_mounth) 
	{
		now_time.tm_mon+=counts;
		now_time.tm_mon=divid_result(now_time.tm_mon,12,&res);
		if(res)
		{
			type=enm_date_year;
			counts=res;
		}		
	}
    if(type==enm_date_year) 
	{
		now_time.tm_year+=counts;
	}
	return mktime(&now_time);
}
static long offset_date_time(long base,long starttime,long endtime,int circletype,int interval)
{
	long start=0;
	long last_start=starttime;
	long end;
	if(starttime>base||circletype==0)
	{
		return starttime;
	}
	while(1)
	{
		start=transfer_period_time(starttime,circletype,interval);
		if(start>base)
		{
			break;
		}
		last_start=start;
	}

	end=last_start+(endtime-starttime);
	if(end>=base)
	{
		return last_start;
	}
	else
	{
		return start;
	}
	return starttime;
}
static int free_date_time(struct Date_t*pdate_src)
{
	struct list_head*pos=NULL;
	struct list_head*posn=NULL;
	struct Date_time_t *pstdatetime=NULL;
	if(list_empty(&(pdate_src->date)))
	{
			return 0;
	}
	list_for_each_safe(pos, posn, &(pdate_src->date))
	{
		list_del(pos);
		pstdatetime=(struct Date_time_t *)pos->data;
		list_del(&(pstdatetime->used_left));
		if(pdate_src->group)
		{
			delete_group_datetime_timer(pdate_src->group,pstdatetime);
		}		
		free(pos);
	}	
	return 0;
}

static int cmp_used_date(struct list_head *_new, struct list_head *q)
{
	struct Date_time_t *pstdatetime_src=get_date_time_ptr(_new);
	struct Date_time_t *pstdatetime_dst=get_date_time_ptr(q);
	
	int end_src=pstdatetime_src->startoffset+(pstdatetime_src->endtime-pstdatetime_src->starttime);
	int end_dst=pstdatetime_dst->startoffset+(pstdatetime_dst->endtime-pstdatetime_dst->starttime);
	
	return (end_src-end_dst);
}
static int cmp_left_date(struct list_head *_new, struct list_head *q)
{
	struct Date_time_t *pstdatetime_src=get_date_time_ptr(_new);
	struct Date_time_t *pstdatetime_dst=get_date_time_ptr(q);
	return (pstdatetime_src->startoffset-pstdatetime_dst->startoffset);
}

static int comp_date(char*task,void *args,char *param)
{
	struct Date_t*pdate_src=(struct Date_t*)task;	
	struct Date_t*pdate_dst=(struct Date_t*)args;
	if(!task)
	{
		return 0;
	}
	if(!args)// free date
	{
		free_date_time(pdate_src);
		return 2;
	}
	if(pdate_src->refid==pdate_dst->refid)
	{
		return 1;
	}
	return 0;
}

static int comp_date_time(char*task,void *args,char *param)
{
	struct Date_time_t*pdate_src=(struct Date_time_t*)task;	
	struct Date_time_t*pdate_dst=(struct Date_time_t*)args;
	if(!task||!args)
	{
		return 0;
	}
	if(pdate_src->date==pdate_dst->date
		&&pdate_src->starttime==pdate_dst->starttime
		&&pdate_src->endtime==pdate_dst->endtime)
	{
		return 1;
	}
	return 0;
}
//struct list_head*date_add_time(long base,struct Date_t*date,struct Date_time_t*datetime)
struct list_head*date_add_time(long base,void*pdate,long starttime,long endtime)
{
	struct list_head*node=NULL;
	struct Date_t*date=(struct Date_t*)pdate;
	struct Date_time_t*datetime=NULL;
	struct Date_time_t stdatetime;
	stdatetime.date=date;
	stdatetime.starttime=starttime;
	stdatetime.endtime=endtime;
	stdatetime.startoffset=0;
	if(stdatetime.endtime==0)
	{
		stdatetime.endtime=stdatetime.starttime;
	}	
	datetime=&stdatetime;
	if(NULL==(node=list_search_do(&(date->date),comp_date_time,(void*)datetime,NULL)))
	{
		if(node==table_list_add(&(date->date),(char*)datetime,sizeof(struct Date_time_t)))
	   	{
			datetime=(struct Date_time_t*)node->data;
			INIT_LIST_HEAD(&(datetime->used_left));
			
			long period=offset_date_time(base,datetime->starttime,datetime->endtime,date->circletype,date->interval);
			datetime->startoffset=period;
			if(period<base)
			{
				period=period+(datetime->endtime-datetime->starttime);
				if(period>base)
				{
					add_list_sort(&(date->used),&(datetime->used_left),cmp_used_date);
				}
			}
			else// not in sope
			{
				add_list_sort(&(date->left),&(datetime->used_left),cmp_left_date);
			}
	   	}	
	}
	return node;
}

struct list_head* add_date(int refid,int circletype,int interval,int enable,struct list_head *head)
{
	struct list_head *node=NULL;
	struct Date_t stdate;
	struct Date_time_t stdatetime;
	memset(&stdate,0,sizeof(stdate));
	stdate.circletype=circletype;
	stdate.interval=interval;
	stdate.enable=enable;
	stdate.refid=refid;
	stdate.refptr=NULL;
	stdate.group=NULL;	
	stdate.args=NULL;
	stdate.htimer=NULL;
	stdate.timeid=0;
	node=list_search_do(head,comp_date,(void*)(&stdate),NULL);
	if(!node)
	{
		if(!(node=table_list_add(head,(char*)(&stdate),sizeof(stdate))))
		{				
			printf("eeror\n");
			return NULL;
		}
		struct Date_t *pstdate=(struct Date_t *)node->data;
		INIT_LIST_HEAD(&(pstdate->date));
		INIT_LIST_HEAD(&(pstdate->used));
		INIT_LIST_HEAD(&(pstdate->left));
		
	}
    return node;
}
int delete_date(int refid,struct list_head *head)
{
	struct list_head *node=NULL;

	struct Date_t stdate;
	struct Date_t *pstdate=NULL;
	memset(&stdate,0,sizeof(stdate));
	stdate.circletype=0;
	stdate.interval=0;
	stdate.enable=1;
	stdate.refid=refid;
	stdate.refptr=NULL;
	date_lock();
	node=list_search_do(head,comp_date,(void*)(&stdate),NULL);
	if(node)
	{
		pstdate=(struct Date_t*)node->data;
		if(pstdate->timeid)
		{
			timer_del(pstdate->htimer,pstdate->timeid);
		}
		free_date_time(pstdate);
		pstdate->refptr=NULL;		
		list_del(node);		
		free(node);
	}
	date_unlock();
	return 0;
}
static int sort_date_time(long base,struct Date_t*date)
{
	struct Date_time_t*datetime=NULL;
	struct list_head*pos=NULL;
	struct list_head*posn=NULL;
	long period=0;
	long end=0;
	if(list_empty(&(date->date)))
	{
			return -1;
	}
	list_for_each_safe(pos, posn, &(date->date))
	{
		datetime=(struct Date_time_t*)pos->data;
		end=datetime->endtime-datetime->starttime+datetime->startoffset;
		period=offset_date_time(base,datetime->startoffset,end,date->circletype,date->interval);
		datetime->startoffset=period;
		list_del(&(datetime->used_left));
		if(period<base)
		{
			period=period+(datetime->endtime-datetime->starttime);
			if(period>base)
			{
				add_list_sort(&(date->used),&(datetime->used_left),cmp_used_date);
			}
		}
		else// not in sope
		{
			add_list_sort(&(date->left),&(datetime->used_left),cmp_left_date);
		}	
	}
	return 0;
}
static void date_start_func(void *user_data);

static int start_date_time(struct Date_t *pstdate,void*htimer,long base)
{

	struct Date_time_t*datetime=NULL;
	int tms=0;
	int tms_start=0;
	if(!list_empty(&(pstdate->used)))
	{
		datetime=get_date_time_ptr(pstdate->used.next);		
		tms=datetime->endtime-datetime->starttime+datetime->startoffset-base;
	}
	if(!list_empty(&(pstdate->left)))
	{
		datetime=get_date_time_ptr(pstdate->left.next);		
		tms_start=datetime->starttime-base;
	}
	if(tms_start==0 && tms==0)
	{
		return 0;
	}
	/*if(tms_start<tms)
	{
		pstdate->timeid=timer_add(htimer,tms_start*1000,0,date_start_func,datetime);
	}
	else
	{
		pstdate->timeid=timer_add(htimer,tms*1000,0,date_start_func,datetime);
	}*/
	if(tms_start<tms)
	{
		tms=tms_start;
	}
	pstdate->timeid=timer_add(htimer,tms*1000,0,date_start_func,datetime);
	return 0;
}
/*
int process_date_time(long base,struct Date_time_t*datetime)
{
	int start_stop=0;
	long end=datetime->endtime-datetime->starttime+datetime->startoffset;

	if(datetime->endtime == datetime->starttime)
	{
		start_stop=0;
	}
	else if(end>=base)//start
	{
		start_stop=1;
	}
	else //stop
	{
		start_stop=-1;
	}	
	return start_stop;
}
*/
static struct Date_t *delete_date_time(struct Date_time_t*datetime)
{
	struct list_head *node=NULL;
	struct list_head *head=NULL;
	struct Date_t *pstdate=datetime->date;
	int res=0;
	if(pstdate->circletype==0)
	{
		node=(struct list_head *)((char*)datetime-offsetof(struct list_head,data));
		list_del(&(datetime->used_left));
		list_del(node);

		if(pstdate->group)
		{
			delete_group_datetime_timer(pstdate->group,datetime);
		}
		if(list_empty(&(pstdate->date)))
		{
			if(pstdate->timeid)
			{
				timer_del(pstdate->htimer,pstdate->timeid);
			}
		    head=(struct list_head *)((char*)pstdate-offsetof(struct list_head,data));
			list_del(head);
			free(head);
			pstdate=NULL;
		}
		free(node);

	}
	return pstdate;
}

static void date_start_func(void *user_data)
{
	struct Date_time_t*datetime=(struct Date_time_t *)user_data;
	struct Date_t *pstdate=NULL;
	long base=0;
	long end=0;
	int start_stop=0;
	date_lock();
	if(!datetime||!datetime->date)
	{
		date_unlock();
		return;
	}
	pstdate=datetime->date;
	pstdate->timeid=0;
	base=get_now_seconds(0);
	end=datetime->endtime-datetime->starttime+datetime->startoffset;
	if(datetime->endtime == datetime->starttime)
	{
		start_stop=0;
	}
	else if(end>=base)//start
	{
		start_stop=1;
	}
	else //stop
	{
		start_stop=-1;
	}	
	sort_date_time(base,pstdate);
	if(pstdate->cb_func)
	{
		pstdate->cb_func(pstdate->refptr,start_stop,(void*)datetime);
	}
	if(start_stop<=0)
	{	
		pstdate=delete_date_time(datetime);
		if(!pstdate)
		{
			date_unlock();
			return;
		}
	}
	start_date_time(pstdate,pstdate->htimer,base);
	date_unlock();
}

int set_date_relation(struct list_head *head,int refid,void*refptr,void*htimer,long base,int (*cb_func)(void*refptr,int start_stop,void*args),void*args)
{
	struct list_head *node=NULL;
	struct Date_t stdate;
	struct Date_t *pstdate=NULL;
	memset(&stdate,0,sizeof(stdate));
	stdate.circletype=0;
	stdate.interval=0;
	stdate.enable=1;
	stdate.refid=refid;
	stdate.refptr=NULL;
	node=list_search_do(head,comp_date,(void*)(&stdate),NULL);
	if(!node)
	{
		return -1;
	}
	pstdate=(struct Date_t *)node->data;
	pstdate->refptr=refptr;
	pstdate->cb_func=cb_func;
	pstdate->htimer=htimer;
	pstdate->args=args;
	return start_date_time(pstdate,pstdate->htimer,base);	
}




int get_date_args_by_time(void*datetime,void**args,void**refptr)
{
	struct Date_t *pstdate=NULL;

	struct Date_time_t*date_time=(struct Date_time_t*)datetime;
	if(!date_time)
	{
		return -1;
	}
	pstdate=date_time->date;
	if(args)
	{
		*args=pstdate->args;
	}
	if(refptr)
	{
		*refptr=pstdate->refptr;
	}
	return 0;
}

struct Group_date_t
{
	//sig_mutex_t lock;
	long timeid;
	void *htimer;
	void *refptr;
	void*args;
	int (*cb_func)(void*refptr,int start_stop,void*args);
	struct list_head date;//date=used+left
	struct list_head *date_table;
};
static int Group_sort_date_time(long base,struct Group_date_t *pgroup,void**minptr)
{
	struct date_ptr_t *pstdata=NULL;
	struct Date_t *pstdate=NULL;
	struct list_head*pos=NULL;
	struct list_head*posn=NULL;
	int minival=0;
	struct Date_time_t*last=NULL;
	if(list_empty(&(pgroup->date)))
	{
			return -1;
	}
	list_for_each_safe(pos, posn, &(pgroup->date))	
	{
		pstdata=(struct date_ptr_t *)pos->data;
		pstdate=(struct Date_t *)pstdata->ptr;
		sort_date_time(base,pstdate);
		if(!list_empty(&(pstdate->used)))
		{
			struct Date_time_t*datetime=get_date_time_ptr(pstdate->used.next);
			int tms=datetime->endtime-datetime->starttime+datetime->startoffset-base;
			if(tms>0)
			{
				if(minival>tms)
				{
					minival=tms;
					last=datetime;
				}
				else if(minival==0)
				{
					minival=tms;
					last=datetime;					
				}
			}
		}
	}
	if(last)
	{
		if(minptr)
		{
			*minptr=last;
		}
	}
	return minival;
}
int Group_get_date_time(void *group,int (*func)(void*refptr,void*args,void*out,int len),void*args,void*out,int len)
{
	struct date_ptr_t *pstdata=NULL;
	struct Date_t *pstdate=NULL;
	struct list_head*pos=NULL;
	struct list_head*posn=NULL;
	struct Group_date_t *pgroup=group;
	if(!pgroup||!func)
	{
		return -1;
	}
	if(list_empty(&(pgroup->date)))
	{
			return -1;
	}	
	list_for_each_safe(pos, posn, &(pgroup->date))	
	{
		pstdata=(struct date_ptr_t *)pos->data;
		pstdate=(struct Date_t *)pstdata->ptr;
		if(!list_empty(&(pstdate->used)))
		{
			func(pstdate->refptr,args,out,len);
		}
	}
	return 0;

}
int Group_add_date(void*group,int refid,void*refptr)
{
	struct Group_date_t *pgroup=(struct Group_date_t *)group;

	struct list_head *node=NULL;
	struct list_head *date_table=pgroup->date_table;
	struct Date_t *pstdate=NULL;
	struct Date_t stdate;
	memset(&stdate,0,sizeof(stdate));
	stdate.circletype=0;
	stdate.interval=0;
	stdate.enable=0;
	stdate.refid=refid;
	stdate.refptr=refptr;
	node=list_search_do(date_table,comp_date,(void*)(&stdate),NULL);    
    if(!node)
	{
		return -1;
	}
    pstdate =  (struct Date_t *)node->data;     
	pstdate->refptr=refptr;
	pstdate->cb_func=NULL;
	pstdate->htimer=NULL;
	pstdate->group=pgroup;	

	struct date_ptr_t stdata;
	stdata.ptr=(char*)pstdate;
	if(!(node=table_list_add(&(pgroup->date),(char*)(&stdata),sizeof(struct date_ptr_t))))
	{				
		printf("eeror\n");
		return -1;
	}
	return 0;
}
static int delete_group_datetime_timer(void*group,struct Date_time_t*pstdatetime)
{
	struct Group_date_t *pgroup=(struct Group_date_t *)group;

	if(!pgroup||!pstdatetime)
	{
		return -1;
	}
	if(!pgroup->htimer||pgroup->timeid==0)
	{
		return -1;
	}	
    if(timer_get_params(pgroup->htimer,pgroup->timeid)==(void*)pstdatetime)
	{
		timer_del(pgroup->htimer,pgroup->timeid);
		pgroup->timeid=0;
	}
	return 0;
}

static int group_delete_date(struct Group_date_t *pgroup,struct Date_t *pstdate)
{
	struct date_ptr_t *pstdata=NULL;
	struct list_head*pos=NULL;
	struct list_head*posn=NULL;
	if(list_empty(&(pgroup->date)))
	{
			return -1;
	}
	list_for_each_safe(pos, posn, &(pgroup->date))	
	{
		pstdata=(struct date_ptr_t *)pos->data;
		if(pstdate==(struct Date_t *)pstdata->ptr||!pstdate)
		{
			list_del(pos);
			pstdate==(struct Date_t *)pstdata->ptr;
			pstdate->group=NULL;			
			free(pos);
		}		
	}
	return 0;
}

static void group_start_func(void *user_data)
{
	struct Date_time_t*datetime=(struct Date_time_t *)user_data;
	struct Date_t *pstdate=NULL;
	struct Date_t *pstdate_tmp=NULL;
	struct Date_time_t*datetime_tmp=NULL;

	struct Group_date_t *pgroup=NULL;
	long base=0;
	long end=0;
	int start_stop=0;
	
	date_lock();
	if(!datetime||!datetime->date)
	{
		
		date_unlock();
		return;
	}
	pstdate=datetime->date;
	pgroup=(struct Group_date_t *)pstdate->group;
	if(!pgroup)
	{
		date_unlock();
		return;
	}
    //group_lock
	
	base=get_now_seconds(0);
	end=datetime->endtime-datetime->starttime+datetime->startoffset;
	if(datetime->endtime == datetime->starttime)
	{
		start_stop=0;
	}
	else if(end>=base)//start
	{
		start_stop=1;
	}
	else //stop
	{
		start_stop=-1;
	}	
	int tms_start=Group_sort_date_time(base,pgroup,(void**)&datetime_tmp);
	if(pgroup->cb_func)
	{
		pgroup->cb_func(pgroup->refptr,start_stop,(void*)datetime);
	}
	if(start_stop<=0)
	{	
		pstdate_tmp=delete_date_time(datetime);
		if(!pstdate_tmp)
		{
			group_delete_date(pgroup,pstdate);
			date_unlock();
			return;
		}
		
	}
	if(datetime_tmp)
	{
		pgroup->timeid=timer_add(pgroup->htimer,tms_start*1000,0,group_start_func,(void*)datetime_tmp);
	}
	//start_group_date(pgroup,pgroup->htimer,base);
	date_unlock();
}

int start_group_date(void*group,void*htimer,long base,
							int (*rule_append)(void*refptr,void*args,void*out,int len),void*args,void*out,int len)
{
    struct Date_time_t*datetime=NULL;
	struct Group_date_t *pgroup=(struct Group_date_t *)group;
	int tms_start=Group_sort_date_time(base,pgroup,(void**)&datetime);
	Group_get_date_time(pgroup,rule_append,args,out,len);
	if(datetime)
	{
		pgroup->timeid=timer_add(htimer,tms_start*1000,0,group_start_func,datetime);
	}
	return 0;
}

static int comp_group(char*task,void *args,char *param)
{
	struct Group_date_t *src=(struct Group_date_t *)task;
	struct Group_date_t *dst=(struct Group_date_t *)args;
	if(!dst)
	{
		if(src->timeid)
		{
			timer_del(src->htimer,src->timeid);
		}
		group_delete_date(src,NULL);
		return 2;
	}
	if(src->refptr==dst->refptr)
	{
		return 1;
	}
	return 0;
}

struct list_head *Group_add(struct list_head *head,void*ptr,struct list_head *date_table,
								void*htimer,int (*cb_func)(void*refptr,int start_stop,void*args))
{
	struct list_head *node=NULL;
	struct Group_date_t *pgroup=NULL;

	struct Group_date_t stgroup;
	stgroup.refptr=ptr;
	stgroup.date_table=date_table;
	stgroup.htimer=htimer;
	stgroup.cb_func=cb_func;
	stgroup.args=NULL;
	node=list_search_do(head,comp_group,(void*)(&stgroup),NULL);
	if(!node)
	{
		if(!(node=table_list_add(&(pgroup->date),(char*)(&stgroup),sizeof(struct Group_date_t))))
		{				
			printf("eeror\n");
			return NULL;
		}	
		pgroup=(struct Group_date_t *)node->data;
		INIT_LIST_HEAD(&(pgroup->date));
		//INIT_LIST_HEAD(&(pgroup->used));
		//sig_mutex_init(&(pgroup->lock), NULL)
	}
	return node;
}
int delete_group(struct list_head *head)
{
	date_lock();
	list_search_do(head,comp_group,NULL,NULL);
	date_unlock();
	return 0;
}

//============================================================



