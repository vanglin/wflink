#ifndef __SOCKET_THREAD_H__
#define __SOCKET_THREAD_H__

struct key_buf_t
{
	int maxsize;
	int len;
	char buf[0];
};

struct socket_t
{
	pthread_mutex_t lock;
	int fd; 
	int threadfd;
	int used;
	struct socket_t*relate;
	void *pool;	
	unsigned long srcaddr;
	int srcport;
	unsigned long dstaddr;
	int dstport;
	struct key_buf_t *buf;
};
void *list_conn_get_pool(void*list_conn);

void *create_list_conn(int maxconns,void *thread_pool);
void destory_list_conn(void*args);

int conn_send(void*comm,char*buf,int len);
int conn_close(char*data,void*args);
int default_client_reconnect(void*args,int (*login)(void*args));

struct socket_t *  conn_alloc(void*list_pool,int fd,unsigned long srcaddr,int srcport,unsigned long dstaddr,int dstport);

void* tcp_client_recv(void*list_conn,char*addr,int port,char*bindaddr,int bindport,
							int (*login)(void*args),
							int (*logout)(void*args,int (*login)(void*args)),
							int (*read_do)(void*args,int (*process_do)(char*buf,int len,void*args)),
							int (*process_do)(char*buf,int len,void*args));
int tcp_server_listening(void*list_conn,char*host,int port,int thread_recv,
									int (*login)(void*args),
									int (*read_do)(void*args,int (*process_do)(char*buf,int len,void*args)),
									int (*process_do)(char*buf,int len,void*args));

int tcp_server_file(void*list_conn,char*name,int thread_recv,
							int (*login)(void*args),
							int (*read_do)(void*args,int (*process_do)(char*buf,int len,void*args)),
							int (*process_do)(char*buf,int len,void*args));

int default_wait_poll(int fd,int (*proc)(char*buf,int len,void*args),void*args);


void*udp_create_setting(void*list_conn,int start,int end,int step);
void udp_free_setting(void*setting);

/*port==-1 alloc setting is required
 port>0   just create udp bind port*/
struct socket_t * udp_create(void*setting,unsigned long ips,int port);
int udp_sendto(struct socket_t*conn,char*buf,int len,unsigned long ips,int port);
int udp_recvfrom(struct socket_t*conn,char*buf,int len,unsigned long *ips,int *port);
int socket_get_addr(struct socket_t *device,unsigned long *ips,int *port);
int socket_get_local_addr(struct socket_t *device,unsigned long *ips,int *port);
int socket_get_invalid(struct socket_t *device,int *fd);
struct socket_t *socket_get_relate(struct socket_t *device);
int socket_set_relate(struct socket_t *device,struct socket_t *peer,unsigned long ips,int port);
int socket_set_addr(struct socket_t *device,unsigned long ips,int port);
int udp_server(struct socket_t * conn,
							int (*read_do)(void*args,int (*process_do)(char*buf,int len,void*args)),
							int (*process_do)(char*buf,int len,void*args));



#endif
