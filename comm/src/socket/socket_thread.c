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
#include <poll.h>
#include "socket_utils.h"
#include "socket_thread.h"
#include "sig_utils.h"
#define err_log(fmt...) \
do{\
	printf("%s:%s [%d] ",__FILE__,__FUNCTION__, __LINE__);\
	printf(fmt);\
}while(0)

struct socket_pool_t
{
	sig_lock_t lock;
	sig_cond_t cond;	
    void *thread_pool; 
	struct list_cache_t conns;
};



/*******************************************************************************************************


******************************************************************************************************/


void *list_conn_get_pool(void*list_conn)
{
	void*thread_pool=NULL;
	struct socket_pool_t*plist_conn=(struct socket_pool_t*)list_conn;
	sig_lock_read(&(plist_conn->lock));
	thread_pool=plist_conn->thread_pool;
	sig_unlock_rw(&(plist_conn->lock));
	return thread_pool;
}
static int list_conn_get_nums(struct socket_pool_t*list_conn)
{
	int nums=0;
	sig_lock_read(&(list_conn->lock));
	nums=list_conn->conns.num;
	sig_unlock_rw(&(list_conn->lock));
	return nums;
}
static int init_conn_data(void*data,void*args)
{
	struct socket_t*conn=(struct socket_t*)data;
	conn->fd=-1;
	conn->threadfd=-1;
	conn->pool=args;
	conn->used=0;
	conn->relate=NULL;
	conn->buf=NULL;
	
	sig_mutex_init(&(conn->lock),NULL);
	return 0;
}

void *create_list_conn(int maxconns,void *thread_pool)
{
	struct socket_pool_t*list_conn=(struct socket_pool_t*)malloc(sizeof(struct socket_pool_t));
	if(!list_conn)
	{
		return NULL;
	}
	list_conn->thread_pool=thread_pool;
	sig_rwlock_init(&(list_conn->lock),NULL);
	init_list_cache(&(list_conn->conns),maxconns,sizeof(struct socket_t),init_conn_data,(void*)list_conn);
	return list_conn;
}


void destory_list_conn(void*args)
{
	struct socket_pool_t*list_conn=(struct socket_pool_t*)args;
	if(!list_conn)
	{
		return ;
	}
	sig_lock_rw(&(list_conn->lock));
	list_cache_destroy(&(list_conn->conns),conn_close);
	sig_unlock_rw(&(list_conn->lock));
	free(args);
}
/************************************************************************************************

****************************************************************************************************/

struct socket_t *  conn_alloc(void*list_pool,int fd,unsigned long srcaddr,int srcport,unsigned long dstaddr,int dstport)
{
	struct socket_t *conn=NULL;
	struct socket_pool_t*list_conn=(struct socket_pool_t*)list_pool;
	if(!list_conn)
	{
		return NULL;
	}
	sig_lock_rw(&(list_conn->lock));
	conn=list_cache_alloc(&(list_conn->conns));
	sig_unlock_rw(&(list_conn->lock));
	if(!conn)
	{
		return NULL;
	}	
	conn->fd=fd;
	conn->threadfd=-1;
	conn->pool=list_pool;
    conn->srcport=srcport;
    conn->srcaddr=srcaddr;
    conn->dstport=dstport;
    conn->dstaddr=dstaddr;
	conn->used=1;
	return conn;
}
int conn_close(char*data,void*args)
{
	struct socket_pool_t*list_conn=NULL;
	struct socket_t *conn=(struct socket_t *)data;
	if(!conn)
	{
		return -1;
	}
	sig_mutex_lock(&(conn->lock));
	if(!conn->used)
	{
		sig_mutex_unlock(&(conn->lock));
		return 0;
	}
	list_conn=(struct socket_pool_t*)conn->pool;
	if(conn->threadfd!=-1)
	{
		close(conn->threadfd);
		conn->threadfd=-1;
	}	
	if(conn->fd!=-1)
	{
		err_log("conn->fdfd=%d\n",conn->fd);
		close(conn->fd);
		conn->fd=-1;
	}
	if(conn->buf)
	{
		free(conn->buf);
		conn->buf=NULL;
	}
	conn->used=0;
	sig_mutex_unlock(&(conn->lock));
	if(!list_conn)
	{
		return -1;
	}
	sig_lock_rw(&(list_conn->lock));
	list_cache_free(&(list_conn->conns),data);
	sig_unlock_rw(&(list_conn->lock));
	return 0;
}
int conn_send(void*comm,char*buf,int len)
{
	int res=0;
	struct socket_t*conn=(struct socket_t*)comm;
	if(!conn)
	{
		return -1;
	}
	
	sig_mutex_lock(&(conn->lock));
	if(conn->fd!=-1)
	{
		res=write(conn->fd,buf,len);
	}
	sig_mutex_unlock(&(conn->lock));
	return res;
}
static int default_read_do(void*args,int (*process_do)(char*buf,int len,void*args))
{
	int res=0;
	int fd=-1;
	char buf[4096]={0};
	
	struct socket_t * conn=(struct socket_t *)args;
	if(!conn)
	{
		return -1;
	}
	sig_mutex_lock(&(conn->lock));
	fd=conn->fd;
	sig_mutex_unlock(&(conn->lock));
	if(fd==-1)
	{
		return -1;
	}
	sig_mutex_lock(&(conn->lock));
	res=read(fd,buf,sizeof(buf));
	sig_mutex_unlock(&(conn->lock));
	err_log("res=%d,fd=%d\n",res,fd);
	if((res>0)&&process_do)
	{
		process_do(buf,res,(char*)conn);
	}
	return res;
}
int default_client_reconnect(void*args,int (*login)(void*args))
{
	int fd=-1;
	struct socket_t * conn=(struct socket_t *)args;
	if(!conn)
	{
		return -1;
	}
	sig_mutex_lock(&(conn->lock));
	if(conn->fd!=-1)
	{
		close(fd);
	}
	conn->fd=-1;
	fd=tcp_client_socket(conn->srcaddr,conn->srcport,conn->dstaddr,conn->dstport);
	conn->fd=fd;
	sig_mutex_unlock(&(conn->lock));
	if(fd!=-1&&login)
	{
		login(conn);
	}
	return fd;
}

/*********************************************************************************************


**********************************************************************************************/

static int poll_client_proc(void*args,
						int (*login)(void*args),
						int (*logout)(void*args,int (*login)(void*args)),
						int (*read_do)(void*args,int (*process_do)(char*buf,int len,void*args)),
						int (*process_do)(char*buf,int len,void*args))
{
	struct pollfd pfds[1]; 
	int used=0;
	struct socket_t * conn=(struct socket_t *)args;
	if(!conn)
	{
		return -1;
	}
	sig_mutex_lock(&(conn->lock));
	int fd=conn->fd;
	sig_mutex_unlock(&(conn->lock));
	if(login)
	{
		login(conn);
	}
	if(!read_do)
	{
		read_do=default_read_do;
	}
	
	for(;;)
	{
		int ret=0;
		pfds[0].fd = fd;  
		pfds[0].events = POLLIN; 
		pfds[0].revents=0;
		ret = poll(pfds, 1, 1000);
		//err_log("poll res=%d\n",ret);
		if(ret<0)
		{
			err_log("epoll error\n");
			break;
		}
		else if(ret==0)
		{
			//err_log("timeout now\n");
			sig_mutex_lock(&(conn->lock));	
			used=conn->used;
			sig_mutex_unlock(&(conn->lock));
			if(used)
			{
				if((fd==-1)&&logout)
				{
					fd=logout((void*)conn,login);
				}
				continue;
			}			
			else
			{
				break;
			}
		}
		ret=read_do((void*)conn,process_do);

		if(ret<0)// 0 is sucess
		{
			if(logout)
			{
				fd=logout((void*)conn,login);
			}
			else
			{
				break;
			}
		}
	}
	err_log("close alrady now\n");
	conn_close((char*)conn,NULL);
	return -1;   
}

static int tcp_thread_start(void*list_conn,void*args,int fd,unsigned long host,int port,int thread_recv,
									int (*login)(void*args),int (*logout)(void*args,int (*login)(void*args)),
									int (*read_do)(void*args,int (*process_do)(char*buf,int len,void*args)),
									int (*process_do)(char*buf,int len,void*args));

static int epoll_server_proc(void*list_conn,int sockfd,int thread_recv,unsigned long addr,int port,
						int (*read_do)(void*args,int (*process_do)(char*buf,int len,void*args)),
						int (*login)(void*args),
						int (*process)(char*buf,int len,void*args))
{
	int res=0;
	int epollfd=-1;
	int max_total_conns=list_conn_get_nums(list_conn);
	int i =0;
	
	struct epoll_event *eventList=(struct epoll_event *)malloc(sizeof(struct epoll_event)*max_total_conns);
	if(!eventList)
	{
		return -1;
	}
	epollfd=epoll_create(max_total_conns);
	struct epoll_event event;
	event.events=EPOLLIN|EPOLLET;
	event.data.fd=sockfd;
	
	if(epoll_ctl(epollfd,EPOLL_CTL_ADD,sockfd,&event)<0)
	{
		err_log("epoll add fd:%d\n",sockfd);
		close(epollfd);
		return -1;
	}
	if(!read_do)
	{
		read_do=default_read_do;
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
				err_log("epoll error\n");
				goto end;
			}
			if(eventList[i].data.fd==sockfd)
			{
				struct sockaddr_in sin;
				socklen_t len=sizeof(struct sockaddr_in);
				bzero(&sin,len);				
				int confd=accept(sockfd,(struct sockaddr *)&sin,&len);
				if(confd<0)
				{
					err_log("connect error\n");
					goto end;
				}
				struct socket_t * conn=conn_alloc(list_conn,confd,addr,port,sin.sin_addr.s_addr,sin.sin_port);
				if(conn)
				{
					if(thread_recv)
					{
						tcp_thread_start(list_conn,(void*)conn,-1,0,0,0,login,NULL,read_do,process);
					}
					else
					{
						 if(login)
					 	{
							login((void*)conn);
					 	}
						event.events=EPOLLIN|EPOLLET;
						event.data.ptr=conn;
						epoll_ctl(epollfd,EPOLL_CTL_ADD,confd,&event);
					}
				}
			}	
			else 
			{
				struct socket_t * conn=(struct socket_t *)eventList[i].data.ptr;
				res=read_do(conn,process);
				if(res<=0)
				{
					if(res<0)err_log("read error %d,%p\n",res,conn);
					event.data.ptr=conn;
					epoll_ctl(epollfd, EPOLL_CTL_DEL, conn->fd, &event);
					conn_close((char*)conn,NULL);
				}				
			}
		}
	}	
end:
	close(epollfd);
	close(sockfd);
	return 0;
}

/*********************************************************************************************


**********************************************************************************************/

struct thread_socket_t
{
	sig_mutex_t lock;
	sig_cond_t cond;
	int fd;
	void *args;
	void*pool;
	unsigned long addr;
	int port;
	int thread_recv;
	int (*read_do)(void*args,int (*process_do)(char*buf,int len,void*args));
	int (*process_do)(char*buf,int len,void*args);
	int (*login)(void *args);
	int (*logout)(void*args,int (*login)(void*args));
};


static void*thread_process(void*args)
{
	void *comm=NULL;
	unsigned long srcaddr=0;
	int srcport=0;
	int thread_recv=0;
	struct thread_socket_t *group=(struct thread_socket_t *)args;
	if(!group)
	{
		return NULL;
	}
	err_log("thread_process\n");
	sig_mutex_lock(&(group->lock));
	int (*read_do)(void*args,int (*process_do)(char*buf,int len,void*args))=group->read_do;
	int (*login)(void*args)=group->login;
	int (*logout)(void*args,int (*login)(void*args))=group->logout;
	int (*process_do)(char*buf,int len,void*args)=group->process_do;
	int sockfd=group->fd;
	void*list_conn=group->pool;
	comm=group->args;
	srcaddr=group->addr;
	srcport=group->port;
	thread_recv=group->thread_recv;
	sig_cond_signal(&(group->cond));
	sig_mutex_unlock(&(group->lock));
	err_log("sockfd=%d comm=%p\n",sockfd,comm);
	if(sockfd==-1&&comm)
	{
		poll_client_proc(comm,login,logout,read_do,process_do);
	}
	else
	{
		epoll_server_proc(list_conn,sockfd,thread_recv,srcaddr,srcport,read_do,login,process_do);
	}
	return NULL;
}
static int tcp_thread_start(void*list_conn,void*args,int fd,unsigned long host,int port,int thread_recv,
									int (*login)(void*args),int (*logout)(void*args,int (*login)(void*args)),
									int (*read_do)(void*args,int (*process_do)(char*buf,int len,void*args)),
									int (*process_do)(char*buf,int len,void*args))
{
	
	struct thread_socket_t group;

	group.fd=fd;
	group.args=args;
	group.pool=list_conn;
	
	group.read_do=read_do;
	group.process_do=process_do;
	group.login=login;	
	group.logout=logout;
	group.thread_recv=thread_recv;

	group.addr=host;
	group.port=port;

	sig_mutex_init(&(group.lock),NULL);
	sig_cond_init(&(group.cond),NULL);
	start_thread(thread_process,(void*)&group,NULL);
	sig_mutex_lock(&(group.lock));
    sig_cond_timedwait(&(group.cond),&(group.lock),1000);
	sig_mutex_unlock(&(group.lock));
	return 0;	
}

/*********************************************************************************************


**********************************************************************************************/
/*thread_recv 0xff
  0xf0
  0x0f
  0x00
  higer lower
  higer: if thread new or this thread listening process
  lower: if accept a connect ,if new thread or add poll to processs
*/

int tcp_server_listening(void*list_conn,char*host,int port,int thread_recv,
									int (*login)(void*args),
									int (*read_do)(void*args,int (*process_do)(char*buf,int len,void*args)),
									int (*process_do)(char*buf,int len,void*args))
{
	int sockfd=-1;
	unsigned long  srcaddr=socket_addr_int(host);
	sockfd=tcp_server_socket(srcaddr,port,list_conn_get_nums(list_conn));
	if(sockfd==-1)
	{
		return -1;
	}
	if((thread_recv&0xf0))
	{
		return tcp_thread_start(list_conn,NULL,sockfd,srcaddr,port,(thread_recv&0x0f),login,NULL,read_do,process_do);
	}
	return epoll_server_proc(list_conn,sockfd,(thread_recv&0x0f),srcaddr,port,read_do,login,process_do);
}
int tcp_server_file(void*list_conn,char*name,int thread_recv,
							int (*login)(void*args),
							int (*read_do)(void*args,int (*process_do)(char*buf,int len,void*args)),
							int (*process_do)(char*buf,int len,void*args))
{
	int sockfd=-1;
	sockfd=file_server_socket(name,list_conn_get_nums(list_conn));
	if(sockfd==-1)
	{
		return -1;
	}
	if((thread_recv&0xf0))
	{
		return tcp_thread_start(list_conn,NULL,sockfd,0,0,(thread_recv&0x0f),login,NULL,read_do,process_do);
	}	
	return epoll_server_proc(list_conn,sockfd,(thread_recv&0x0f),0,0,read_do,login,process_do);

}

void*tcp_client_recv(void*list_conn,char*addr,int port,char*bindaddr,int bindport,
							int (*login)(void*args),
							int (*logout)(void*args,int (*login)(void*args)),
							int (*read_do)(void*args,int (*process_do)(char*buf,int len,void*args)),
							int (*process_do)(char*buf,int len,void*args))
{

	unsigned long srcaddr=socket_addr_int(bindaddr);
	unsigned long dstaddr=socket_addr_int(addr);	
	int fd=tcp_client_socket(srcaddr,bindport,dstaddr,port);
	if(-1==fd)
	{
		err_log("thread_process\n");
		//return NULL;
	}
	struct socket_t * conn=conn_alloc(list_conn,fd,srcaddr,bindport,dstaddr,port);
	if(!conn)
	{
		close(fd);
		return NULL;
	}
	tcp_thread_start(list_conn,(void*)conn,-1,0,0,0,login,logout,read_do,process_do);
	return (void*)conn;
}

int default_wait_poll(int fd,int (*proc)(char*buf,int len,void*args),void*args)
{
	struct pollfd pfds[1]; 
	int res =0;
	char buf[1024];
	if(fd==-1)
	{
		return -1;
	}
	do{
	    pfds[0].fd = fd;  
	    pfds[0].events = POLLIN; 
		res=poll(pfds,1,1000);		
		if(res>0)
		{
			res=read(fd,buf,sizeof(buf));
		}
		
	}while(0);  
	if(proc)
	{
		proc(buf,res,args);
	}	
	return 0;
}

/***********************************************************************************************************



**************************************************************************************************************/

struct udp_setting_t
{
	 int udp_port_end;
	 int udp_port_start;
	 int udp_port_step;
	 int udp_port_now;
	 void*list_conn;
};

void*udp_create_setting(void*list_conn,int start,int end,int step)
{
	struct udp_setting_t *udpsetting=malloc(sizeof(struct udp_setting_t));
	udpsetting->udp_port_now=start;
	udpsetting->udp_port_end=end;
	udpsetting->udp_port_start=start;
	udpsetting->udp_port_step=step;
	udpsetting->list_conn=list_conn;
	return udpsetting;
}
void udp_free_setting(void*setting)
{
	struct udp_setting_t *udpsetting=(struct udp_setting_t *)setting;
	if(!udpsetting)
	{
		return;
	}
	free(udpsetting);
	return ;
}

static int udp_port_get_now(void*setting,int x)
{
	int now=0;
	struct udp_setting_t *udpsetting=(struct udp_setting_t *)setting;
	if(!udpsetting)
	{
		return 0;
	}	
	now= udpsetting->udp_port_now;
	if(x==now)
	{
		now=0;
	}
	else
	{
		udpsetting->udp_port_now = now + udpsetting->udp_port_step;
		if(udpsetting->udp_port_now>udpsetting->udp_port_end)
		{
			udpsetting->udp_port_now=udpsetting->udp_port_start;
		}
	}
	return now;
}

/*port==-1 alloc setting is required
 port>0   just create udp bind port*/
struct socket_t * udp_create(void*setting,unsigned long ips,int port)
{
	struct udp_setting_t *udpsetting=(struct udp_setting_t *)setting;

	int fd=udp_socket(ips,port,udp_port_get_now,setting);
	if(-1==fd)
	{
		err_log("thread_process\n");
		return NULL;
	}
	struct socket_t * conn=conn_alloc(udpsetting->list_conn,fd,ips,port,0,0);
	if(!conn)
	{
		close(fd);
		return NULL;
	}
	return conn;
}





static int udp_send(struct socket_t * conn,char*buf,int len,unsigned long ips,int port)
{
	int res=0;
	struct sockaddr_in sin;
	int sin_len = sizeof(sin);	
	//struct socket_t * udp_ptr=(struct socket_t *)conn;
	if(!conn)
	{
		return -1;
	}
	if(ips==0)
	{
		ips=conn->dstaddr;
		port=conn->dstport;
	}
	sin.sin_family = PF_INET;
	sin.sin_addr.s_addr=ips;	
	sin.sin_port=htons(port);

	if(-1!=conn->fd)
	{
			res = sendto(conn->fd,buf,len,0, (struct sockaddr *) &sin, sin_len);
	}	
	return res;	
}
static int udp_read(struct socket_t * conn,char*buf,int len,unsigned long *ips,int *port)
{
	int res=0;
	struct sockaddr_in sin;
	int sin_len = sizeof(sin);	
	//struct socket_t * udp_ptr=(struct socket_t *)conn;
	if(!conn)
	{
		return -1;
	}

	if(-1!=conn->fd)
	{
		res = recvfrom(conn->fd,buf,len,0, (struct sockaddr *)&sin, &sin_len);
	}
	if(ips)
	{
		*ips=sin.sin_addr.s_addr;
	}
	if(port)
	{
		*port=htons(sin.sin_port);
	}
	return res;		
}

int udp_sendto(struct socket_t*conn,char*buf,int len,unsigned long ips,int port)
{
	int res=0;
	//struct socket_t * udp_ptr=(struct socket_t *)conn;
	if(!conn)
	{
		return -1;
	}
	sig_mutex_lock(&(conn->lock));	
	res=udp_send(conn,buf,len,ips,port);
	sig_mutex_unlock(&(conn->lock));	
	return res;	
}
int udp_recvfrom(struct socket_t*conn,char*buf,int len,unsigned long *ips,int *port)
{
	int res=0;
	//struct socket_t * udp_ptr=(struct socket_t *)conn;
	if(!conn)
	{
		return -1;
	}
	sig_mutex_lock(&(conn->lock));	
	res=udp_read(conn,buf,len,ips,port);
	sig_mutex_unlock(&(conn->lock));	
	return res;		
}


int socket_get_addr(struct socket_t *device,unsigned long *ips,int *port)
{
	if(!device)
	{
		return -1;
	}
	sig_mutex_lock(&(device->lock));
	if(ips)
		*ips=device->dstaddr;
	if(port)
		*port=htons(device->dstport);
	sig_mutex_unlock(&(device->lock));
	return 0;
}

int socket_get_local_addr(struct socket_t *device,unsigned long *ips,int *port)
{
	struct sockaddr_in sockAddr;		 
	int   iLen=sizeof(sockAddr);

	//struct socket_t *device=(struct socket_t *)args;
	if(!device)
	{
		return -1;
	}
	sig_mutex_lock(&(device->lock));
	getsockname(device->fd,(struct   sockaddr   *)&sockAddr,&iLen);
	if(ips)
		*ips=sockAddr.sin_addr.s_addr;
	if(port)
		*port=htons(sockAddr.sin_port);
	sig_mutex_unlock(&(device->lock));
	return 0;
}
int socket_get_invalid(struct socket_t *device,int *fd)
{
	int pfd=-1;
	//struct socket_t *device=(struct socket_t *)args;
	if(!device)
	{
		return -1;
	}
	sig_mutex_lock(&(device->lock));
	pfd=device->fd;
	sig_mutex_unlock(&(device->lock));
	if(fd)
		*fd=pfd;
	if(pfd==-1)
		return -1;
	return 0;
}
struct socket_t *socket_get_relate(struct socket_t *device)
{
	//struct socket_t *device=(struct socket_t *)args;
	if(!device)
	{
		return NULL;
	}
	return device->relate;
}
int socket_set_relate(struct socket_t *device,struct socket_t *peer,unsigned long ips,int port)
{
	//struct socket_t *device=(struct socket_t *)args;
	if(!device)
	{
		return -1;
	}
	sig_mutex_lock(&(device->lock));
	device->relate=peer;
	device->dstaddr=ips;		
	device->dstport=port;
	sig_mutex_unlock(&(device->lock));
	return 0;
}
int socket_set_addr(struct socket_t *device,unsigned long ips,int port)
{
	//struct socket_t *device=(struct socket_t *)args;
	if(!device)
	{
		return -1;
	}	
	sig_mutex_lock(&(device->lock));
	device->dstaddr=ips;		
	device->dstport=port;
	sig_mutex_unlock(&(device->lock));
	return 0;
}

static int udp_default_read_do(void*args,int (*process_do)(char*buf,int len,void*args))
{
	int res=0;
	int fd=-1;
	char buf[4096]={0};
	struct sockaddr_in sin;
	int sin_len = sizeof(sin);	
	struct socket_t *peer=NULL;
	
	struct socket_t * conn=(struct socket_t *)args;
	if(!conn)
	{
		return -1;
	}
	sig_mutex_lock(&(conn->lock));
	fd=conn->fd;
	sig_mutex_unlock(&(conn->lock));
	if(fd==-1)
	{
		return -1;
	}
	sig_mutex_lock(&(conn->lock));
	res = recvfrom(fd,buf,sizeof(buf),0, (struct sockaddr *)&sin, &sin_len);
	peer=conn->relate;
	sig_mutex_unlock(&(conn->lock));
	err_log("res=%d,fd=%d\n",res,fd);
	if((res>0)&&peer)
	{
		res=udp_sendto(peer,buf,res,0,0);
	}
	return res;
}

int udp_server(struct socket_t * conn,
							int (*read_do)(void*args,int (*process_do)(char*buf,int len,void*args)),
							int (*process_do)(char*buf,int len,void*args))
{
	if(!read_do)
	{
		read_do=udp_default_read_do;
	}
	return tcp_thread_start(NULL,(void*)conn,-1,0,0,0,NULL,NULL,read_do,process_do);
}

