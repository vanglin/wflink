#ifndef __SOCKET_UTILS__
#define __SOCKET_UTILS__

unsigned long socket_addr_int(char*addr);
int socket_addr_string(unsigned long ips,char*addr,int len);

int file_server_socket(char*filename,int max_listen);

int file_tryconnect(char*filename);

int  tcp_client_socket(unsigned long srcaddr,int srcport,unsigned long dstaddr,int dstport);

int tcp_server_socket(unsigned long addr,int listport,int max_listen);

int  socketpair_new(int *sockets);
int udp_socket(unsigned long ips,int port,int(*udp_port_get)(void*setting,int x),void*setting);

#endif



