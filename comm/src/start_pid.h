#ifndef __NET_CONFGI__H_
#define __NET_CONFGI__H_

#ifdef SOCKET_THREAD
#include "socket_thread.h"
#endif

void* start_main(int argc, char *argv[],char*optionlong,void*pool,
					int (*default_option)(char ch,char*arg),
					int (*command_process)(char*buf,int len,void*args));
int start_pid(void* listconn,char*filename,int newthread,char *xargs,int (*command_process)(char*buf,int len,void*args));
void file_remotecontrol(char *data,int fd);
void* start_run(int argc, char *argv[],char*optionlong,void*pool,
					int (*default_option)(char ch,char*arg),
					int (*command_process)(char*buf,int len,void*args),
					int (*run_start)(void*xargs));

#endif
