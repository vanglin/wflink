#include <stdio.h>  
#include <stdlib.h>  
#include <errno.h>  
#include <string.h>  
#include <unistd.h>  
#include <sys/un.h> 
#include <netdb.h>

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

#ifndef AF_LOCAL
#define AF_LOCAL AF_UNIX
#define PF_LOCAL PF_UNIX
#endif
#define err_log printf
#define SOCKET_BUFFER_SIZE 4096


int file_server_socket(char*filename,int max_listen)
{
	struct sockaddr_un sunaddr;
	int res;
	int fd=-1;
	if(!filename)
	{
		return -1;
	}
	unlink(filename);
	fd = socket(PF_LOCAL, SOCK_STREAM, 0);
	if (fd < 0) {
		printf("Unable to create control socket: %s\n", strerror(errno));
		return -1;
	}
	memset(&sunaddr, 0, sizeof(sunaddr));
	sunaddr.sun_family = AF_LOCAL;
	strncpy(sunaddr.sun_path, filename, sizeof(sunaddr.sun_path));
	res = bind(fd, (struct sockaddr *)&sunaddr, sizeof(sunaddr));
	if (res) {
		printf( "Unable to bind socket to %s: %s\n", filename, strerror(errno));
		close(fd);
		fd = -1;
		return -1;
	}
	res = listen(fd, max_listen);
	if (res < 0) {
		printf( "Unable to listen on socket %s: %s\n", filename, strerror(errno));
		close(fd);
		fd = -1;
		return -1;
	}	
	return fd;
}


int file_tryconnect(char*filename)
{
	struct sockaddr_un sunaddr;
	int res;
	int app_socket_client = socket(PF_LOCAL, SOCK_STREAM, 0);
	if (app_socket_client < 0) {
		fprintf(stderr, "Unable to create socket: %s\n", strerror(errno));
		return -1;
	}
	memset(&sunaddr, 0, sizeof(sunaddr));
	sunaddr.sun_family = AF_LOCAL;
	strncpy(sunaddr.sun_path, filename, sizeof(sunaddr.sun_path));
	res = connect(app_socket_client, (struct sockaddr *)&sunaddr, sizeof(sunaddr));
	if (res) {
		close(app_socket_client);
		app_socket_client = -1;
		return -1;
	} 
	return app_socket_client;
}

int socket_addr_string(unsigned long ips,char*addr,int len)
{
	struct in_addr inaddr;
	inaddr.s_addr=ips;
	if(addr)
	{
		snprintf(addr,len,"%s",inet_ntoa(inaddr));
	}
	return 0;
}
unsigned long socket_addr_int(char*addr)
{
	int res=0;
	struct in_addr saddt;
	if(!addr)
	{
		return 0;
	}
	res=inet_pton(AF_INET, addr, (void *)&saddt);
	if(res<=0)
	{
		return 0;
	}
	return ((unsigned long)saddt.s_addr);
	//return inet_addr(addr);
}

int  tcp_client_socket(unsigned long srcaddr,int srcport,unsigned long dstaddr,int dstport)
{
	int res=0;
	int sockfd=-1;
	struct sockaddr_in addr;
	struct sockaddr_in local_addr;
	if(!dstaddr)
	{
		return -1;
	}
    
    addr.sin_family=PF_INET;
    addr.sin_port=htons(dstport);
    addr.sin_addr.s_addr=dstaddr;
	if(srcaddr)
	{
		local_addr.sin_family=PF_INET;
		local_addr.sin_port=htons(srcport);
		local_addr.sin_addr.s_addr=srcaddr;
	}
	sockfd = socket(PF_INET,SOCK_STREAM,0);
	if(sockfd < 0)
	{
		printf("ERROR Unable to create socket!\n");
		return -1;
	}
	int on=1;
	setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

	/*if(srcaddr&&bind(sockfd, (struct sockaddr *)(&local_addr), sizeof(struct sockaddr)) < 0)
	{
		printf("ERROR bind socket!\n");
		close(sockfd);
		return -1;
	}*/
	res = connect(sockfd, (struct sockaddr *)(&addr), sizeof(struct sockaddr));
	if(res)
	{
		err_log("failed to connect %d\n",sockfd);
		close(sockfd);
		return -1;
	}
	return sockfd;
}
int tcp_server_socket(unsigned long addr,int listport,int max_listen)
{
    struct sockaddr_in serverSockaddr;
    int sockfd;
	if(!addr)
	{
		return -1;
	}
    if((sockfd=socket(AF_INET,SOCK_STREAM,0))==-1)
    {
        perror("failed for socekt");
        return -1;
    }
    serverSockaddr.sin_family=AF_INET;
    serverSockaddr.sin_port=htons(listport);
    serverSockaddr.sin_addr.s_addr=addr;
    bzero(&(serverSockaddr.sin_zero),8);

    int on=1;
    setsockopt(sockfd,SOL_SOCKET,SO_REUSEADDR,&on,sizeof(on));

    if(bind(sockfd,(struct sockaddr *)&serverSockaddr,sizeof(struct sockaddr))==-1)
    {
        perror("failed for bind");
		close(sockfd);
        return -1;
    }

    if(listen(sockfd,max_listen)==-1)
    {
        perror("failed for listen");
		close(sockfd);
        return -1;;
    }
	return sockfd;
}

int  socketpair_new(int *sockets)
{
	int result=0;
	result = socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sockets);
	if(-1 == result)
	{
		printf("socketpair error!\n");
		return -1;
	}
	int bufferSize = SOCKET_BUFFER_SIZE;
	setsockopt(sockets[0], SOL_SOCKET, SO_SNDBUF, &bufferSize, sizeof(bufferSize));
	setsockopt(sockets[0], SOL_SOCKET, SO_RCVBUF, &bufferSize, sizeof(bufferSize));
	setsockopt(sockets[1], SOL_SOCKET, SO_SNDBUF, &bufferSize, sizeof(bufferSize));
	setsockopt(sockets[1], SOL_SOCKET, SO_RCVBUF, &bufferSize, sizeof(bufferSize));
	return 0;
}
int udp_socket(unsigned long ips,int port,int(*udp_port_get)(void*setting,int x),void*setting)
{
	int i=0;
	int x=0;
	struct sockaddr_in us;
	int s = socket(PF_INET, SOCK_DGRAM, 0);
	if (s < 0) {
			err_log("Unable to allocate socket: %s\n",  strerror(errno));
	} else {
			long flags = fcntl(s, F_GETFL);
			fcntl(s, F_SETFL, flags | O_NONBLOCK);
	}	
	us.sin_family = PF_INET;
	us.sin_addr.s_addr=ips;	
	if(port<=0&&udp_port_get)
	{
		x=udp_port_get(setting,0);
	}
	else
	{
		x=port;
	}
	i=x;
	for(;;)
	{
		us.sin_port = i;
		if (!bind(s, (struct sockaddr *)(&us), sizeof(struct sockaddr)))
		{
			err_log("sucess bind: %s\n");
			break;
		}
		err_log("Unable to bind socket: %s\n",  strerror(errno));
		if(port>0)
		{
			break;
		}
		i = udp_port_get(setting,x);
		if(i==0)
		{
			break;
		}
	}	
	if(i==0)
	{
		close(s);
		s=-1;
	}	
	return s;
}

