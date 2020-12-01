#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <fcntl.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>
#include <net/if.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <linux/if_ether.h>

#include "cJSON.h"
#include "wflink_config.h"
#include "wflink_logs.h"
#include "cjson_parse.h"

int get_mac_and_ip_by_interface(unsigned char *plocal_macaddr, char  *peth_dev_name,unsigned int *hostaddr)
{
	int fd;
	struct ifreq ifreq;

	if( NULL == plocal_macaddr )
	{
		goto err;
	}

	if( NULL == peth_dev_name )
	{
		peth_dev_name = HOST_CONTROL_INTERFACE;
	}

	fd = socket(PF_INET, SOCK_DGRAM, 0);
	if (fd == -1)
	{
		printf("Socket: %s, errno = %d", strerror(errno), errno);
		goto err;
	}

	strcpy(ifreq.ifr_name, peth_dev_name);
	if (ioctl(fd, SIOCGIFHWADDR, &ifreq) < 0)
	{
		printf("IOCTL:errno = %d\n", errno);
		close(fd);
		goto err;
	}
	memcpy(plocal_macaddr, ifreq.ifr_hwaddr.sa_data, ETH_ALEN);
    if(!ioctl(fd, SIOCGIFADDR, &ifreq))
	{
		if(hostaddr)
			*hostaddr=ntohl(((struct sockaddr_in*)&ifreq.ifr_addr)->sin_addr.s_addr);
	} 
	close(fd);

	return 0;
err:
	return -1;    
}

static void default_config(wflink_cfg_t *cfg)
{
	if(cfg)
	{
		memset(cfg, 0 ,sizeof(wflink_cfg_t));
		cfg->http.bind_server_port = 8089;
		cfg->coap.bind_client_port = 6684;
		cfg->coap.proxy_server_port = 5683;
		cfg->coap.server_port = 5684;
		cfg->coap.transport = "tls";
		cfg->coap.proxy_address = NULL;
		cfg->coap.server_address = NULL;
	}
}
static int parse_config(cJSON * json,void * dst)
{
	wflink_cfg_t *cfg = (wflink_cfg_t *)dst;
	default_config(cfg);
	cJSON *child = cJSON_GetObjectItem(json, "global");
	if(child)
	{
		
	}
	child = cJSON_GetObjectItem(json, "http");
	if(child)
	{
		cJSON_GetStringByKey(child, "bind_server_address", cfg->http.bind_server_address);
		cJSON_GetIntByKey(child, "bind_server_port", cfg->http.bind_server_port);
	}
	child = cJSON_GetObjectItem(json, "coap");
	if(child)
	{
		cJSON_GetStringByKey(child, "bind_client_address", cfg->coap.bind_client_address);
		cJSON_GetIntByKey(child, "bind_client_port", cfg->coap.bind_client_port);
		cJSON_GetStringByKey(child, "proxy_address", cfg->coap.proxy_address);
		cJSON_GetIntByKey(child, "proxy_server_port", cfg->coap.proxy_server_port);
		cJSON_GetStringByKey(child, "server_address", cfg->coap.server_address);
		cJSON_GetIntByKey(child, "server_port", cfg->coap.server_port);
		cJSON_GetStringByKey(child, "transport", cfg->coap.transport);
		cJSON_GetStringByKey(child, "psk_user", cfg->coap.psk_user);
		cJSON_GetStringByKey(child, "psk_key", cfg->coap.psk_key);
	}
	struct in_addr addr;
	char localmac[6];
	unsigned int dsp_host_ipaddr=0xc0a80101;
	if(!cfg->http.bind_server_address)
	{
		get_mac_and_ip_by_interface(localmac, HOST_CONTROL_INTERFACE, &dsp_host_ipaddr);
		addr.s_addr=htonl(dsp_host_ipaddr);
		cfg->http.bind_server_address = strdup(inet_ntoa(addr));
	}
	return 0;
}

int load_config(wflink_cfg_t *cfg, char *filename)
{
	if(!cfg)
		return -1;
	if(!filename)
		filename = WFLINK_DEFAULT_PATH;
	return read_json_from_file(filename, parse_config, (void *)cfg, 1);
}
