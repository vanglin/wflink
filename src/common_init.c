#include <stdlib.h>  
#include <errno.h>  
#include <string.h>  
#include <unistd.h>  
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
#include "wflink.h"
#include "wflink_config.h"

extern wflink_context_t g_wflink_ctx;
extern wflink_cfg_t g_wflink_cfg;

void print_usage()
{
	printf("Usage:\n");
	printf("myapp [-M ?][-m ?][-p ?][--tcpcli][--catchsig][--help] \n");
	printf("M: max users\n");
	printf("m: max calls for each user\n");
	printf("p: sip bind port\n");								
	printf("tcpcli: run tcp cli server\n");
	printf("catchsig: if catch sig for success exit when core down\n");
}

//!!! args_ana [not completed]
int args_ana(int argc, char *argv[])
{
    int res = 0;
    /* args analyse*/
    int opt;
    int digit_optind = 0;
    int option_index = 0;
    char *tmp = NULL;
    char *optstring = "f:";
    static struct option long_options[] = {
		{"help", no_argument, NULL, 'h'},
        {0, 0, 0, 0}
    };

    if(!(tmp=strstr(argv[0],"/")))
    {
    	tmp=argv[0];
    }
    else
    {
    	tmp++;
    }
    g_wflink_ctx.appname=strdup(tmp);

    while ( (opt = getopt_long(argc, argv, optstring, long_options, &option_index)) != -1)
    {
         switch (opt)
         {
         	case 'f':
					g_wflink_ctx.cfgfilename = strdup(optarg);
				break;
			case 'h':
            default:
					if(opt != 'h')
					{
                    	printf("wrong argument %s\n", argv[optind - 1]);
					}
					print_usage();
                    res = -1;
                    break;
         }
    }
        return res;
}

static void recv_signal(int sig)
{
	exit(0);
}
int catch_signal()
{
	signal(SIGSEGV, recv_signal);
	signal(SIGINT, recv_signal);
	signal(SIGPIPE, recv_signal);
	signal(SIGTERM, recv_signal);
	return 0;
}

