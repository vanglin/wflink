#include <stdio.h>  
#include <stdlib.h>  
#include <errno.h>  
#include <string.h>  
#include <unistd.h>  
#include <sys/un.h> 

#include <fcntl.h>  
#include <sys/types.h>  
#include <arpa/inet.h>  
#include <netinet/in.h>  
#include <sys/socket.h>  
#include <sys/epoll.h>  
#include <sys/wait.h>  
#include "stddef.h"
#include <pthread.h>
#include <time.h>
#include <signal.h>
#include <getopt.h>
#include <poll.h>
#include "socket_utils.h"
#include "start_pid.h"
#define err_log(fmt...) \
do{\
	printf("%s:%s [%d] ",__FILE__,__FUNCTION__, __LINE__);\
	printf(fmt);\
}while(0)

#ifndef SOCKET_THREAD

typedef pthread_mutex_t pid_mutex_t;
typedef  pthread_cond_t pid_cond_t;
#define pid_mutex_init pthread_mutex_init
#define	pid_mutex_lock pthread_mutex_lock
#define	pid_mutex_unlock pthread_mutex_unlock
#define	pid_cond_init pthread_cond_init
#define	pid_cond_signal pthread_cond_signal

static int pid_cond_timedwait(pid_cond_t *cond,pid_mutex_t*mutex ,int ms)
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

struct thread_param_t
{
	pid_mutex_t lock;
	pid_cond_t cond;
	int fd;
	int maxconns;	
	int thread_recv;
	int (*read_do)(void*args,int (*process_do)(char*buf,int len,void*args));
	int (*process_do)(char*buf,int len,void*args);
	int (*login)(void*args);
};
static int pid_new_thread(void*callbak,void *data,void*out)
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
static int default_read_do(void*args,int (*process_do)(char*buf,int len,void*args))
{
	int res=0;
	int fd=(int)((long)args);
	char buf[4096]={0};
	if(fd==-1)
	{
		return -1;
	}
	res=read(fd,buf,sizeof(buf));
	if((res>0)&&process_do)
	{
		process_do(buf,res,args);
	}
	return res;
}
static int poll_file_proc(void*unused)
{
	struct pollfd pfds[1]; 
	
	struct thread_param_t *group=(struct thread_param_t *)unused;
	if(!group)
	{
		return -1;
	}	
	pid_mutex_lock(&(group->lock));	
	int fd=group->fd;
	int (*read_do)(void*args,int (*process_do)(char*buf,int len,void*args))=group->read_do;
	int (*process_do)(char*buf,int len,void*args)=group->process_do;
	int (*login)(void*args)=group->login;
	pid_cond_signal(&(group->cond));
	pid_mutex_unlock(&(group->lock));	
	if(!read_do)
	{
		read_do=default_read_do;
	}	
	if(fd==-1)
	{
		return -1;
	}	
	if(login)
	{
		login((void*)((long)fd));
	}
	if(!read_do)
	{
		read_do=default_read_do;
	}
	for(;;)
	{
		pfds[0].fd = fd;  
		pfds[0].events = POLLIN; 
		pfds[0].revents=0;
		int ret = poll(pfds, 1, -1);
		if(ret<0)
		{
			err_log("epoll error\n");
			break;
		}
		else if(ret==0)
		{
			continue;
		}
		ret=read_do((void*)((long)fd),process_do);

		if(ret<=0)
		{
			break;
		}
	}
	close(fd);
	return 0;   
}
static int tcp_accept_file(int sockfd,
							int (*login)(void*args),
							int (*read_do)(void*args,int (*process_do)(char*buf,int len,void*args)),
							int (*process_do)(char*buf,int len,void*args))
{

	struct thread_param_t group;
	group.fd=sockfd;
	group.read_do=read_do;
	group.process_do=process_do;
	group.login=login;
	pid_mutex_init(&(group.lock),NULL);
	pid_cond_init(&(group.cond),NULL);
	pid_new_thread(poll_file_proc,(void*)&group,NULL);
	pid_mutex_lock(&(group.lock));
    pid_cond_timedwait(&(group.cond),&(group.lock),1000);
	pid_mutex_unlock(&(group.lock));
	return 0;
}

static void *listener(void *unused)
{
	int res=0;
	int epollfd=-1;
	int max_total_conns=0;
	int i =0;
	int thread_recv	=0;
	struct thread_param_t *group=(struct thread_param_t *)unused;
	if(!group)
	{
		return NULL;
	}
	
	pid_mutex_lock(&(group->lock));	
	int sockfd=group->fd;
	int (*read_do)(void*args,int (*process_do)(char*buf,int len,void*args))=group->read_do;
	int (*process_do)(char*buf,int len,void*args)=group->process_do;
	int (*login)(void*args)=group->login;
	max_total_conns=group->maxconns;
	thread_recv=group->thread_recv;
	pid_cond_signal(&(group->cond));
	pid_mutex_unlock(&(group->lock));	
	if(!read_do)
	{
		read_do=default_read_do;
	}	
	
	struct epoll_event *eventList=(struct epoll_event *)malloc(sizeof(struct epoll_event)*max_total_conns);
	if(!eventList)
	{
		return NULL;
	}
	memset(eventList,0,sizeof(struct epoll_event)*max_total_conns);
	epollfd=epoll_create(max_total_conns);
	struct epoll_event event;
	event.events=EPOLLIN|EPOLLET;
	event.data.fd=sockfd;
	
	if(epoll_ctl(epollfd,EPOLL_CTL_ADD,sockfd,&event)<0)
	{
		err_log("epoll add fd:%d\n",sockfd);
		close(epollfd);
		return NULL;
	}

	while(1)
	{
		int timeout=300;
		int ret=epoll_wait(epollfd,eventList,max_total_conns,timeout);

		if(ret < 0 && errno != EINTR)
		{
			err_log("epoll error\n");
			break;
		}
		else if(ret==0)
		{
			continue;
		}

		for(i=0;i<ret;i++)
		{
			if((eventList[i].events == EPOLLERR) || (eventList[i].events== EPOLLHUP))
			{
				err_log("epoll error %d;%d-%d-%d\n",eventList[i].events,EPOLLERR,EPOLLHUP,EPOLLIN);
				goto end;
			}
			if(eventList[i].data.fd==sockfd)
			{
				struct sockaddr_un sin;
				socklen_t len=sizeof(sin);			
				bzero(&sin,len);				
				int confd=accept(sockfd,(struct sockaddr *)&sin,&len);
				if(confd<0)
				{
					err_log("connect error\n");
					goto end;
				}
				if(thread_recv)
				{
					tcp_accept_file(confd,login,read_do,process_do);
				}
				else
				{
					 if(login)
					{
						login((void*)((long)confd));
					}
					event.events=EPOLLIN|EPOLLET;
					event.data.fd=confd;
					epoll_ctl(epollfd,EPOLL_CTL_ADD,confd,&event);
				}


			}	
			else 
			{
				int confd=eventList[i].data.fd;
				res=read_do((void*)((long)confd),process_do);
				if(res<=0)
				{
					event.data.fd=confd;
					epoll_ctl(epollfd, EPOLL_CTL_DEL, confd, &event);
					close(confd);
				}				
			}
		}
	}	
end:
	close(epollfd);
	close(sockfd);
}

struct pid_list_t
{
	int maxconns;
	void*pool;
	int args[0];
};
static struct pid_list_t pid_head;

static void *create_list_conn(int maxconns,void *thread_pool)
{
	pid_head.maxconns=maxconns;
	pid_head.pool=thread_pool;
	return (void*)&pid_head;
}
static int tcp_server_file(void*list_conn,char*name,int thread_recv,
							int (*login)(void*args),
							int (*read_do)(void*args,int (*process_do)(char*buf,int len,void*args)),
							int (*process_do)(char*buf,int len,void*args))
{
	if(!list_conn)
	{
		return -1;
	}
	struct pid_list_t *connhead=(struct pid_list_t*)list_conn;
	int maxconns=connhead->maxconns;
	int sockfd = file_server_socket(name,maxconns);
	if(sockfd==-1)
	{
		return -1;
	}
	struct thread_param_t group;
	group.fd=sockfd;
	group.read_do=read_do;
	group.process_do=process_do;
	group.login=login;
	group.maxconns=maxconns;
	group.thread_recv=(thread_recv&0x0f);
	pid_mutex_init(&(group.lock),NULL);
	pid_cond_init(&(group.cond),NULL);
	if((thread_recv&0xf0))
	{
		pid_new_thread(listener,(void*)&group,NULL);
		pid_mutex_lock(&(group.lock));
		pid_cond_timedwait(&(group.cond),&(group.lock),1000);
		pid_mutex_unlock(&(group.lock));
		
	}
	else
	{
		listener((void*)&group);
	}
	return 0;
}

#endif

/*********************************************************************************************


**********************************************************************************************/

static int file_client_send_to(char*data,int fd,int waitrsp)
{
	int res =0;
	int str_len =0;
	if (write(fd, data, strlen(data) + 1) < 0) {
		err_log( "write() failed: %s\n", strerror(errno));
		return -1;
	}
	if(!waitrsp)
	{
		return 0;
	}
	struct pollfd fds;
	fds.fd = fd;
	fds.events = POLLIN;
	fds.revents = 0;
	do{
		res=poll(&fds, 1, 1000);
		if(!res)
		{
			char *result="result: timeout\r\n\r\n";
			write(STDOUT_FILENO,result,strlen(result));
			break;
		}
		if( res > 0) 
		{
			char buffer[512] = "";		
			if ((str_len=read(fd, buffer, sizeof(buffer) - 1)) <= 0) 
			{
				break;
			}
			if (write(STDOUT_FILENO, buffer, str_len) < 0) 
			{
				err_log("write() failed: %s\n", strerror(errno));
				break;
			}			
		}
	}while(0);
	return 0;
}
void file_remotecontrol(char *data,int fd)
{

	if (data) {
		file_client_send_to(data,fd,1);
		return;
	}
	else
	{
		//cli get_commds
		char option[64];
		char ch;
		int i =0;
		while(1)
		{
			fputs("#CLI>>",stdout);
			ch=fgetc(stdin);
			option[i++]=ch;
			if(ch=='\0'||ch=='\n')
			{
				file_client_send_to(option,fd,1);
				memset(option,0,sizeof(option));
				i=0;
			}
			else if(ch==0x20)
			{
				//sep
			}
			else if(ch=='\t')
			{
				file_client_send_to(option,fd,1);
				fputs(option,stdout);
			}
			if(i>=sizeof(option)-1)
			{
			    fputs("error input too long",stdout);
				fputs(option,stdout);
				memset(option,0,sizeof(option));
				i=0;				
			}
		}

	}
     err_log("\nDisconnected from Asterisk server\n");
}


int start_pid(void* listconn,char*filename,int newthread,char *xargs,int (*command_process)(char*buf,int len,void*args))
{
	int fd=-1;
	char name[128];
	snprintf(name,sizeof(name),"/tmp/%s.txt",filename);
	
	if(!listconn)
	{
		fd=file_tryconnect(name);
		if(fd==-1)
		{
			return -1;
		}
	    file_remotecontrol(xargs,fd);
		close(fd);
	}
	else
	{
		tcp_server_file(listconn,name,newthread,NULL,NULL,command_process);
	}  
	return 0;
}

void* start_main(int argc, char *argv[],char*optionlong,void*pool,
					int (*default_option)(char ch,char*arg),
					int (*command_process)(char*buf,int len,void*args))
{
    int ch;  
	char *xargs=NULL;
	char *tmp=NULL;
	int remoteflags=0;
	char *pidname=NULL;
	void *list_conn=NULL;
	int maxconns=20;
	int newthread=0;
	if(!(tmp=strstr(argv[0],"/")))
	{
		tmp=argv[0];
	}
	else
	{
		for(tmp=tmp;tmp;tmp=strstr(xargs,"/"))
		{
			xargs=tmp+1;
			if(xargs==NULL||*xargs=='\0')
			{
				xargs="noname";
				break;
			}
		}
		tmp=xargs;
		xargs=NULL;
	}
	pidname=tmp;
	char option_buf[64];
	snprintf(option_buf,sizeof(option_buf),"%s%s","rx:m:q:n:",optionlong?optionlong:"");
	
    while ((ch = getopt(argc,argv,option_buf))!=-1)  
    {  
            switch(ch)  
            {  
                    case 'x':  
                            xargs=optarg;  
                            break;  
                    case 'r':  
                            remoteflags=1;  
                            break; 
					case 'm':  
							maxconns=atoi(optarg);	
							break;	
					case 'n':
							newthread=atoi(optarg);	
							break;
                    default:  
							if(default_option)
							{
                       			 default_option(ch,optarg);  
							}
							break;
            }  
    } 
	if(remoteflags)
	{
		list_conn=NULL;
	}
	else
	{
		list_conn=create_list_conn(maxconns,pool);
	}
	start_pid(list_conn,pidname,newthread,xargs,command_process);
	return list_conn;
}

void* start_run(int argc, char *argv[],char*optionlong,void*pool,
					int (*default_option)(char ch,char*arg),
					int (*command_process)(char*buf,int len,void*args),
					int (*run_start)(void*xargs))
{
    int ch;  
	char *xargs=NULL;
	char *tmp=NULL;
	int remoteflags=0;
	char *pidname=NULL;
	void *list_conn=NULL;
	int maxconns=20;
	int newthread=0;
	int fd=-1;
	if(!(tmp=strstr(argv[0],"/")))
	{
		tmp=argv[0];
	}
	else
	{
		
		for(tmp=tmp;tmp;tmp=strstr(xargs,"/"))
		{
			xargs=tmp+1;
			if(xargs==NULL||*xargs=='\0')
			{
				xargs="noname";
				break;
			}
		}
		tmp=xargs;
		xargs=NULL;
	}
	char name[128];
	snprintf(name,sizeof(name),"/tmp/%s.txt",tmp);

	char option_buf[64];
	snprintf(option_buf,sizeof(option_buf),"%s%s","rx:m:q:n:",optionlong?optionlong:"");
	
    while ((ch = getopt(argc,argv,option_buf))!=-1)  
    {  
            switch(ch)  
            {  
                    case 'x':  
                            xargs=optarg;  
                            break;  
                    case 'r':  
                            remoteflags=1;  
                            break; 
					case 'm':  
							maxconns=atoi(optarg);	
							break;	
					case 'n':
							newthread=atoi(optarg);	
							break;
                    default:  
							if(default_option)
							{
                       			 default_option(ch,optarg);  
							}
							break;
            }  
    } 
	if(remoteflags)
	{
		fd=file_tryconnect(name);
		if(fd==-1)
		{
			return NULL;
		}
		file_remotecontrol(xargs,fd);
		close(fd);
		return 0;
	}
	list_conn=create_list_conn(maxconns,pool);
	if(!list_conn)
	{
		return NULL;
	}
	if(run_start)
	{
		run_start(list_conn);
	}
	tcp_server_file(list_conn,name,newthread,NULL,NULL,command_process);
	return list_conn;
}

