#ifndef __WFLINK_CONFIG_H__
#define __WFLINK_CONFIG_H__

#define WFLINK_DEFAULT_PATH "/config/wflink.cfg"
#define HOST_CONTROL_INTERFACE "br0"
//#define HOST_CONTROL_INTERFACE "eno16777736"

typedef struct
{
}wflink_global_cfg_t;

typedef struct
{
	char *bind_server_address; //if null, get by the inteface devName
	int bind_server_port;
}wflink_http_cfg_t;

typedef struct
{
	char *bind_client_address; //if null, get by the inteface devName
	int bind_client_port;
	int proxy_server_port;
	int server_port;
	char *transport;
	char *proxy_address;
	char *server_address;
	char *psk_user;
	char *psk_key;
}wflink_coap_cfg_t;

typedef struct
{
	//wflink_global_cfg_t global;
	wflink_http_cfg_t http;
	wflink_coap_cfg_t coap;
}wflink_cfg_t;

int load_config(wflink_cfg_t *cfg, char *filename);
int get_mac_and_ip_by_interface(unsigned char *plocal_macaddr, char  *peth_dev_name,unsigned int *hostaddr);

#endif
