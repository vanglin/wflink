#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <assert.h>
#include <cJSON.h>
#include "coap2/coap.h"

#include "cjson_parse.h"
#include "state_machine.h"
#include "wflink.h"
#include "wflink_utility.h"
#include "custom_adapt.h"
#include "coap_client.h"
#include "http_server.h"
#include "app_client_session.h"

typedef struct
{
	sig_mutex_t lock;
	char *route;
	sig_lock_t s_lock;
	msg_process process[REQUEST_METHOD_MAX];
}wflink_processor_t;

typedef struct
{
	
	char *registerCode;
	char *appAccount;
	char *accessToken;
	char *refreshToken;
	int tokenTimeout;
	long heartbeat_tid;
	long refreshtoken_tid;
}running_data_t;

extern wflink_context_t g_wflink_ctx;
static char dev_role[8] = "wolink"; //router / wolink
static void *st = NULL;
static running_data_t data_in_memory = {0};

/* Return:
 *  1 - login and session_id right
 *  0 - no login or session_id incorrect
 */
static int is_app_client_login(virtual_construct_t*construct,void*req)
{
	char *cookies = NULL;
	char acs_id[129] = {0};
	construct->get_header(req, "Cookie", &cookies);
	get_cookie(cookies, ACS_ID_COOKIE, acs_id, sizeof(acs_id));
	if(get_acs_by_acs_id(acs_id))
	{
		return 1;
	}
	return 0;
}

/*************************************************************
 *                  INTERFACES START
 *************************************************************/
//!!! not done for all interfaces
int get_test_helloworld(virtual_construct_t*construct,void*req,void*resp)
{
	if(VCONS_COAP == construct->type)
	{
		construct->set_code(resp, 201);
	}
	else
	{
		construct->set_code(resp, 200);	
		construct->set_header(resp, "Content-Type", "text/html");
		construct->set_header(resp, "Content-Length", "12");
	}
	construct->set_body(resp, "Hello World!", 12);
	return 0;
}
int handle_user_login_nonce(virtual_construct_t*construct,void*req,void*resp)
{
	char *body = NULL, *username = NULL, *first_nonce = NULL, *tx_body = NULL;
	char slen[32] = {0};
	int body_len = 0;
	cJSON *body_obj = NULL, *data = NULL, *jsonSend = NULL;
	if(VCONS_HTTP == construct->type)
	{
		construct->get_body(req, &body, &body_len);
		if(body)
		{
			if(body_obj = cJSON_Parse(body))
			{
				if(data = cJSON_GetObjectItem(body_obj, "data"))
				{
					cJSON_GetStringByKey(data, "username", username);
					cJSON_GetStringByKey(data, "firstnonce", first_nonce);
					if(username && first_nonce)
					{
						jsonSend = cJSON_CreateObject();
						acs_handle_login_challenge(jsonSend, username, first_nonce);
						if(tx_body = cJSON_PrintUnformatted(jsonSend))
						{
							construct->set_code(resp, 200);	
							construct->set_header(resp, "Content-Type", MIME_TYPE_JSON);
							construct->set_header(resp, "Content-Length", intIntoString(strlen(tx_body), slen, sizeof(slen)));
							construct->set_body(resp, tx_body, strlen(tx_body));
							free(tx_body);
						}
						cJSON_Delete(jsonSend);
					}
					WF_FREE(username);
					WF_FREE(first_nonce);
				}
				cJSON_Delete(body_obj);
			}
		}
	}
	return 0;
}
int handle_login_proof(virtual_construct_t*construct,void*req,void*resp)
{
	char *body = NULL, *client_proof = NULL, *final_nonce = NULL, *acs_id = NULL, *tx_body = NULL;
	char slen[32] = {0}, cookie[256] = {0};
	int body_len = 0, errcode = 0;
	cJSON *body_obj = NULL, *data = NULL, *jsonSend = NULL;
	if(VCONS_HTTP == construct->type)
	{
		construct->get_body(req, &body, &body_len);
		if(body)
		{
			if(body_obj = cJSON_Parse(body))
			{
				if(data = cJSON_GetObjectItem(body_obj, "data"))
				{
					cJSON_GetStringByKey(data, "clientproof", client_proof);
					cJSON_GetStringByKey(data, "finalnonce", final_nonce);
					if(client_proof && final_nonce)
					{
						jsonSend = cJSON_CreateObject();
						errcode = acs_handle_authentication_request(jsonSend, client_proof, final_nonce, &acs_id);
						if(tx_body = cJSON_PrintUnformatted(jsonSend))
						{
							construct->set_code(resp, 200);	
							construct->set_header(resp, "Content-Type", MIME_TYPE_JSON);
							construct->set_header(resp, "Content-Length", intIntoString(strlen(tx_body), slen, sizeof(slen)));
							if(!errcode && acs_id)
							{
								snprintf(cookie, sizeof(cookie), "Language=en; %s=%s", ACS_ID_COOKIE, acs_id);
								construct->set_header(resp, "Set-Cookie", cookie);
							}
							construct->set_body(resp, tx_body, strlen(tx_body));
							free(tx_body);
						}
						cJSON_Delete(jsonSend);
					}
					WF_FREE(client_proof);
					WF_FREE(final_nonce);
				}
				cJSON_Delete(body_obj);
			}
		}
	}
	return 0;
}
int handle_verifycode(virtual_construct_t*construct,void*req,void*resp)
{
	char *body = NULL, *value = NULL, *tx_body = NULL;
	char slen[32] = {0}, buffer[128] = {0};
	int body_len = 0, errcode = 0, bactive = 0;
	cJSON *body_obj = NULL, *data = NULL, *jsonSend = NULL;
	if(VCONS_HTTP == construct->type)
	{
		if(STATE_WAITACTIVATE != get_current_state(st) || !is_app_client_login(construct, req))
		{
			// !!! cookie SessionID_R3 failed [not planned]
			errcode = -1;
			goto send;
		}
		construct->get_body(req, &body, &body_len);
		if(body)
		{
			if(body_obj = cJSON_Parse(body))
			{
				if(data = cJSON_GetObjectItem(body_obj, "data"))
				{
					// devId is always empty and devId info will be set later in coap activate response handler, see platform_services_process
					//cJSON_GetStringByKey(data, "devId", value);
					//if(value)
					//{
					//	_cfg_func_setObject("devId", value);
					//	free(value);
					//	value = NULL;
					//}
					cJSON_GetStringByKey(data, "psk", value);
					if(value)
					{
						_cfg_func_setObject("psk", value);
						free(value);
						value = NULL;
					}
					cJSON_GetStringByKey(data, "code", value);
					if(value)
					{
						WF_FREE(data_in_memory.registerCode);
						data_in_memory.registerCode = strdup(value);
						free(value);
						value = NULL;
					}
					// !!! 'account' not used now and send response [not planned]
					cJSON_Delete(body_obj);
					goto send;
				}
				cJSON_Delete(body_obj);
			}
		}
	}
	return 0;
send:
	jsonSend = cJSON_CreateObject();
	cJSON_AddNumberToObject(jsonSend, "errcode", errcode);
	tx_body = cJSON_PrintUnformatted(jsonSend);
	cJSON_Delete(jsonSend);
	if(tx_body)
	{
		construct->set_code(resp, 200);	
		construct->set_header(resp, "Content-Type", MIME_TYPE_JSON);
		construct->set_header(resp, "Content-Length", intIntoString(strlen(tx_body), slen, sizeof(slen)));
		construct->set_body(resp, tx_body, strlen(tx_body));
		free(tx_body);
		_cfg_func_getObject("activiated", buffer, sizeof(buffer));
		bactive = atoi(buffer);
		DBGPRINT(DEBUG_TRACE, "errcode = %d, bactive = %d\n", errcode, bactive);
		if(!errcode && !bactive)
		{
			enqueue_state_machine(st, STATE_ACTIVATE);
		}
	}
	return 0;
}

// zzx   interfaces for http and coap
int get_lan_host(virtual_construct_t*construct,void*req,void*resp)
{
	char buffer[125] = {0};
	cJSON *jsonSend = NULL;
	char *tx_body = NULL;
	char nodeName[32] = {0};
	char MACAddress[32] = {0};
	char slen[32] = {0};
	int ret = -1;

	if(VCONS_COAP == construct->type)
	{
		construct->set_code(resp, 201);
	}
	else if(VCONS_HTTP == construct->type)
	{
		construct->set_code(resp, 200);	
	}

	jsonSend = cJSON_CreateObject();
	
	bzero(buffer, sizeof(buffer));
	if ( 0 == tcapi_get("lan_Entry", "IP", buffer)&& 0 != buffer[0])
		cJSON_AddStringToObject(jsonSend, "FristIP", buffer);

	bzero(buffer, sizeof(buffer));
	if ( 0 == tcapi_get("lan_Entry", "netmask", buffer)&& 0 != buffer[0])
		cJSON_AddStringToObject(jsonSend, "FirstMac", buffer);

	ret = get_interface_hwaddr("br0", buffer, sizeof(buffer));
	stringToCapital(buffer);
	mac_add_dot(buffer, MACAddress);
	printf("[%s:%d]:ret :%d !!!===========>\n",__FUNCTION__,__LINE__,ret);
	if( ret==0 )
	{
		cJSON_AddBoolToObject(jsonSend, "FirstEnable",1);
		cJSON_AddStringToObject(jsonSend, "MACAddress", MACAddress);
	}
	else
	{
		cJSON_AddBoolToObject(jsonSend, "FirstEnable",0);
	}

	//bzero(buffer, sizeof(buffer));
	//if ( 0 == tcapi_get("lan_Entry", "DomainName", buffer)&& 0 != buffer[0])
	cJSON_AddStringToObject(jsonSend, "DomainName", ".net");

	cJSON_AddStringToObject(jsonSend, "ID", "lan_entry");

	tx_body = cJSON_PrintUnformatted(jsonSend);
	cJSON_Delete(jsonSend);
	if(tx_body)
	{
		printf("[%s:%d]:tx_body :%s !!!===========>\n",__FUNCTION__,__LINE__,tx_body);
		construct->set_header(resp, "Content-Type", MIME_TYPE_JSON);
		construct->set_header(resp, "Content-Length", intIntoString(strlen(tx_body), slen, sizeof(slen)));
		construct->set_body(resp, tx_body, strlen(tx_body));
		free(tx_body);
	}
	
	return 0;
}
wflink_processor_t g_interfaces[] =
{
#if ONLY_FOR_COMPILE
	{
		.route = "api/null",
		.process[REQUEST_METHOD_GET] = NULL,
		.process[REQUEST_METHOD_POST] = NULL,
	},
	{
		.route = "test/helloworld",
		.process[REQUEST_METHOD_GET] = get_test_helloworld,
		.process[REQUEST_METHOD_POST] = NULL,
	},
#endif
	{
		.route = "/ntwk/lan_host",
		.process[REQUEST_METHOD_GET] = get_lan_host ,
		.process[REQUEST_METHOD_POST] = NULL,
	},
	{
		.route = HTTP_DISCOVERY1_URI,
		.process[REQUEST_METHOD_GET] = NULL,
		.process[REQUEST_METHOD_POST] = handle_user_login_nonce,
	},
	{
		.route = HTTP_DISCOVERY2_URI,
		.process[REQUEST_METHOD_GET] = NULL,
		.process[REQUEST_METHOD_POST] = handle_login_proof,
	},
	{
		.route = HTTP_ACTIVATE_URI,
		.process[REQUEST_METHOD_GET] = NULL,
		.process[REQUEST_METHOD_POST] = handle_verifycode,
	},
};
/*************************************************************
 *                  INTERFACES END
 *************************************************************/

void interfaces_init()
{
	int i = 0;
	for(i = 0; i < sizeof(g_interfaces)/sizeof(g_interfaces[0]); i++)
	{
		sig_mutex_init(&g_interfaces[i].lock, NULL);
		sig_rwlock_init(&g_interfaces[i].s_lock, NULL);
	}
}

int do_process_by_route(char *route, method_type_e method, virtual_construct_t *construct, void *req, void *resp)
{
	char *iroute = NULL;
	sig_lock_t *rw_lock = NULL;
	msg_process *processes = NULL;
	msg_process process = NULL;
	int i = 0;
	int ret = -1;
	if(!route || !req || !resp)
	{
		return -1;
	}
	DBGPRINT(DEBUG_TRACE, "route = %s\n", route);
	for(i = 0; i < sizeof(g_interfaces)/sizeof(g_interfaces[0]); i++)
	{
		sig_mutex_lock(&g_interfaces[i].lock);
		iroute = g_interfaces[i].route;
		rw_lock = &g_interfaces[i].s_lock;
		processes = g_interfaces[i].process;
		sig_mutex_unlock(&g_interfaces[i].lock);
		//if(!strncmp(route, iroute, strlen(iroute)))
		// http path_prefix: /.api, coap path_prefix: /.sys/gateway
		if(strstr(route, iroute))
		{
			process = processes[method];
			if(process)
			{
				(REQUEST_METHOD_GET == method) ? sig_lock_read(rw_lock) : sig_lock_rw(rw_lock);
				ret = process(construct,(void *)req, (void *)resp);
				sig_unlock_rw(rw_lock);
			}
			break;
		}
	}
	return ret;
}

void iterate_processors(char *route, int (*callback)(void *processor, void *args), void *args)
{
	int i, j;
	char *iroute = NULL;
	for(i = 0; i < sizeof(g_interfaces)/sizeof(g_interfaces[0]); i++)
	{	
		sig_mutex_lock(&g_interfaces[i].lock);
		iroute = g_interfaces[i].route;
		if(route)
		{	
			if(!strncmp(route, iroute, strlen(iroute)))
			{
				if(callback)
				{
					callback((void *)&g_interfaces[i], args);
				}
				sig_mutex_unlock(&g_interfaces[i].lock);
				break;
			}
		}
		else
		{
			if(callback)
			{
				callback((void *)&g_interfaces[i], args);
			}
		}
		sig_mutex_unlock(&g_interfaces[i].lock);
	}
}

char *get_processor_property_route(void *arg, int need_lock)
{
	wflink_processor_t *processor = (wflink_processor_t *)arg;
	char *iroute = NULL;
	if(need_lock)sig_mutex_lock(&processor->lock);
	iroute = processor->route;
	if(need_lock)sig_mutex_unlock(&processor->lock);
	return iroute;
}

msg_process *get_processor_property_process(void *arg, int need_lock)
{
	wflink_processor_t *processor = (wflink_processor_t *)arg;
	msg_process *processes = NULL;
	if(need_lock)sig_mutex_lock(&processor->lock);
	processes = processor->process;
	if(need_lock)sig_mutex_unlock(&processor->lock);
	return processes;
}

/*************************************************************
 *                  BELOW IS ABOUT REGISTER/ACTIVATE/LOGIN
 *                  Networking Function Platform
 *************************************************************/ 

#define REGISTER_NOREPLY_MAX (3 | DISCONNECT_FLAG) 
#define REGISTER_ERROR_MAX 3
#define ACTIVATE_NOREPLY_MAX (3 | DISCONNECT_FLAG)
#define ACTIVATE_ERROR_MAX 0
#define LOGIN_NOREPLY_MAX TIMEOUT_FLAG
#define LOGIN_ERROR_MAX TIMEOUT_FLAG
#define SYNC_NOREPLY_MAX 1
#define SYNC_ERROR_MAX 0
#define HEARTBEAT_NOREPLY_MAX (3 | DISCONNECT_FLAG | RELOGIN_FLAG)
#define HEARTBEAT_ERROR_MAX 0
#define REFERSH_NOREPLY_MAX (3 | DISCONNECT_FLAG | RELOGIN_FLAG)
#define REFERSH_ERROR_MAX 0

static int init_data_in_memory()
{
	memset(&data_in_memory, 0, sizeof(data_in_memory));
	data_in_memory.heartbeat_tid = -1;
	data_in_memory.refreshtoken_tid = -1;
	return 0;
}
static int xcoap_refresh(cJSON *jsonSend)
{
	if(!data_in_memory.refreshToken)
		return -1;
	cJSON_AddStringToObject(jsonSend, "refreshToken", data_in_memory.refreshToken);
	return 0;
}
static char *combine_uri(char *dst, int size, char *path)
{
	int transport = 0;
	char host[64] = {0};
	char protocol[16] = {0};
	if(dst)
	{
		get_coap_server_address(host, sizeof(host));
		transport = get_coap_transport();
		switch(transport)
		{
			case COAP_PROTO_UDP:
				strncpy(protocol, "coap", sizeof(protocol));
				break;
			case COAP_PROTO_DTLS:
				strncpy(protocol, "coaps", sizeof(protocol));
				break;
			case COAP_PROTO_TCP:
				strncpy(protocol, "coap+tcp", sizeof(protocol));
				break;
			case COAP_PROTO_TLS:
				strncpy(protocol, "coaps+tcp", sizeof(protocol));
				break;
			default:
				break;
		}
		snprintf(dst, size, "%s://%s%s", protocol, host, path);
	}
	return dst;
}
static void wflink_send_coap_request(void *user_data)
{
	char *body = NULL;
	char *path = (char *)user_data;
	char uri[256] = {0};
	cJSON *data = NULL;
	int ret = 0, noreply_max = 0;
	void *session = NULL, *trans = NULL;
	sig_mutex_lock(&g_wflink_ctx.coapClient.lock);
	session = g_wflink_ctx.coapClient.session;
	sig_mutex_unlock(&g_wflink_ctx.coapClient.lock);
	if(!session)
		return;
	// send heartbeat
	data = cJSON_CreateObject();
	if(COAP_REGISTER_URI == path)
	{
		xcoap_register(data, dev_role);
		noreply_max = REGISTER_NOREPLY_MAX;
	}
	else if(COAP_ACTIVATE_URI == path)
	{
		xcoap_activate(data, data_in_memory.registerCode);
		noreply_max = ACTIVATE_NOREPLY_MAX;
	}
	else if(COAP_LOGIN_URI == path)
	{
		xcoap_login(data);
		noreply_max = LOGIN_NOREPLY_MAX;
	}
	else if(COAP_SYNC_URI == path)
	{
		xcoap_sync(data);
		noreply_max = SYNC_NOREPLY_MAX;
	}
	else if(COAP_HEARTBEAT_URI == path)
	{
		xcoap_heartbeat(data);
		noreply_max = HEARTBEAT_NOREPLY_MAX;
	}
	else if(COAP_REFRESH_URI == path)
	{
		xcoap_refresh(data);
		noreply_max = REFERSH_NOREPLY_MAX;
	}
	else
	{
		DBGPRINT(DEBUG_ERROR, "can't recognize uri[%s]\n", path);
		cJSON_Delete(data);
		return;
	}
	body = cJSON_PrintUnformatted(data);
	cJSON_Delete(data);
	if(body)
	{
		trans = create_coap_request_transaction(REQUEST_METHOD_POST, combine_uri(uri, sizeof(uri), path), body, noreply_max);
		if(data_in_memory.accessToken)
		{
			set_options_access_token(trans, data_in_memory.accessToken);
		}
		ret = send_coap_request(session, trans);
		free(body);
		if(ret)
		{
			DBGPRINT(DEBUG_ERROR, "Send coap request failed!!!\n");
		}
	}
}

static int update_token(cJSON *data)
{
	char *tmpstr = NULL;
	int ret = 0, old_timeout = 0;
	if(!data)
		return;
	cJSON_GetStringByKey(data, "accessToken", tmpstr);
	if(tmpstr)
	{
		WF_FREE(data_in_memory.accessToken);
		data_in_memory.accessToken = tmpstr;
	}
	else
	{
		goto notfound;
	}
	tmpstr = NULL;
	cJSON_GetStringByKey(data, "refreshToken", tmpstr);
	if(tmpstr)
	{
		WF_FREE(data_in_memory.refreshToken);
		data_in_memory.refreshToken = tmpstr;
	}
	old_timeout = data_in_memory.tokenTimeout;
	cJSON_GetIntByKey(data, "timeOut", data_in_memory.tokenTimeout);
	if(old_timeout != data_in_memory.tokenTimeout)
	{
		// send refresh delay
		DBGPRINT(DEBUG_TRACE, "data_in_memory.tokenTimeout = %u(ms), max_uint = %u\n", data_in_memory.tokenTimeout * 1000, (2 << 32) - 1);
		data_in_memory.refreshtoken_tid = timer_replace(g_wflink_ctx.htimer, data_in_memory.refreshtoken_tid, 4000, data_in_memory.tokenTimeout * 1000, wflink_send_coap_request, (void *)COAP_REFRESH_URI);
	}
	return 0;
notfound:
	return -1;
}

static int handle_state_prepare()
{
	int brouter = 0, bwolink = 0;
	int workmode = 0;
	char buffer[128] = {0}, servaddr[128] = {0};
	int ret = 0;
	// wait workmode and get wanip/brlanip
	while(buffer[0] == '\0')
	{
		workmode = _getWorkMode();
		_getDeivceIpAddr(buffer, sizeof(buffer), workmode, "");
		usleep(1000 * 1000);
	}
	// is router?
	get_coap_server_address(servaddr, sizeof(servaddr));
	snprintf(buffer, sizeof(buffer), "traceroute -r %s -m 4 -w 2", servaddr);
	ret = system(buffer);
	brouter = !ret;
	// turn into state STATE_CONN when router or wolink
	if(brouter)
	{
		strncpy(dev_role, "router", sizeof(dev_role));
		goto conn;
	}
	// is wolink?
	bwolink = workmode == 1;
	if(bwolink)
	{
		strncpy(dev_role, "wolink", sizeof(dev_role));
		goto conn;
	}
	DBGPRINT(DEBUG_ERROR, "Device plays a role of STA!!!\n");
	return -1;
conn:
	DBGPRINT(DEBUG_ERROR, "brouter = %d, bwolink = %d\n", brouter, bwolink);
	enqueue_state_machine(st, STATE_CONN);
	return 0;
}
static int handle_state_conn()
{
	// get and judge activiated
	char buffer[128] = {0};
	int ret = 0, bactive = 0;
	cJSON *data = NULL;
	char *body = NULL;
	void *session = NULL;
	_cfg_func_getObject("activiated", buffer, sizeof(buffer));
	bactive = atoi(buffer);
	sig_mutex_lock(&g_wflink_ctx.coapClient.lock);
	session = g_wflink_ctx.coapClient.session;
	sig_mutex_unlock(&g_wflink_ctx.coapClient.lock);
	// create tls connection to send register then wait the response and disconnect
	if(!session)
	{
		start_thread(start_coap_client, (void *)&g_wflink_ctx.coapClient, NULL);
		sig_mutex_lock(&g_wflink_ctx.coapClient.lock);
		sig_cond_timedwait(&g_wflink_ctx.coapClient.cond, &g_wflink_ctx.coapClient.lock, 2 * 1000);
		sig_mutex_unlock(&g_wflink_ctx.coapClient.lock);
		usleep(1000 * 1000);
	}
	if(!bactive)
	{
		// send register
		wflink_send_coap_request((void *)COAP_REGISTER_URI);
	}
	else
	{
		// send login
		wflink_send_coap_request((void *)COAP_LOGIN_URI);
	}
	return 0;
}
static int handle_state_sync()
{
	// send activate
	wflink_send_coap_request((void *)COAP_SYNC_URI);
	return 0;
}
static int handle_state_heartbt()
{
	// send heartbeat immediately and add into timer
	wflink_send_coap_request((void *)COAP_HEARTBEAT_URI);
	assert(-1 == data_in_memory.heartbeat_tid);
	data_in_memory.heartbeat_tid = timer_add(g_wflink_ctx.htimer, 0, COAP_HEARTBEAT_INTERVAL_SEC * 1000, wflink_send_coap_request, (void *)COAP_HEARTBEAT_URI);

	return 0;
}
static int handle_state_waitactivate()
{
	DBGPRINT(DEBUG_INFO, "just change current state into waiting activated\n");
	return 0;
}
static int handle_state_activate()
{
	void *session = NULL;
	DBGPRINT(DEBUG_TRACE, "Start to activate!\n");
	sig_mutex_lock(&g_wflink_ctx.coapClient.lock);
	session = g_wflink_ctx.coapClient.session;
	sig_mutex_unlock(&g_wflink_ctx.coapClient.lock);
	// create tls connection to send activate
	if(!session)
	{
		start_thread(start_coap_client, (void *)&g_wflink_ctx.coapClient, NULL);
		sig_mutex_lock(&g_wflink_ctx.coapClient.lock);
		sig_cond_timedwait(&g_wflink_ctx.coapClient.cond, &g_wflink_ctx.coapClient.lock, 2 * 1000);
		sig_mutex_unlock(&g_wflink_ctx.coapClient.lock);
		usleep(1000 * 1000);
	}
	wflink_send_coap_request((void *)COAP_ACTIVATE_URI);
	return 0;
}

state_process stps[] = {
	init_coap_client,
	handle_state_prepare,
	handle_state_conn,
	handle_state_sync,
	handle_state_heartbt,
	handle_state_waitactivate,
	handle_state_activate,
};

int start_coap_client_state_machine(void *args)
{
	st = init_state_machine(stps, sizeof(stps)/sizeof(stps[0]));
	if(!st)
		return -1;
	init_data_in_memory();
	enqueue_state_machine(st, STATE_INIT);
	enqueue_state_machine(st, STATE_PREPARE);
	return 0;
}

static void error_retransmission(void *userdata)
{
	state_type_t state = (state_type_t)userdata;
	enqueue_state_machine(st, state);
}

/* Handle coap response msg
 * 
 */
int platform_services_process(char*buf,int len,char*args)
{	
	int state = 0, bactive = 0, errcode = 0;
	char buffer[128] = {0};
	char *tmpstr = NULL;
	cJSON *data = NULL, *value = NULL;
	static int register_error_retry = 0;
	data = cJSON_Parse(buf);
	if(!data)
	{
		goto json_err;
	}
	value = cJSON_GetObjectItem(data, "errcode");
	if(value->type == cJSON_Number)
	{
		errcode = value->valueint;
		switch(state = get_current_state(st))
		{
			case STATE_CONN:
				// register | login response
				_cfg_func_getObject("activiated", buffer, sizeof(buffer));
				bactive = atoi(buffer);
				
				if(!bactive)
				{
					switch(errcode)
					{
						case CEC_SUCCESS:
							stop_coap_client(&g_wflink_ctx.coapClient);
							enqueue_state_machine(st, STATE_WAITACTIVATE);
							break;
						case CEC_ARGUMENT_INCOMPLETED:
							stop_coap_client(&g_wflink_ctx.coapClient);
							break;
						case CEC_INTERNAL:
							if(register_error_retry++ < REGISTER_ERROR_MAX)
							{
								timer_add(g_wflink_ctx.htimer, RETRANSMISSION_INTERVAL_SEC * 1000, 0, error_retransmission, (void *)STATE_CONN);
							}
							else
							{
								register_error_retry = 0;
								stop_coap_client(&g_wflink_ctx.coapClient);
							}
							break;
						default:
							stop_coap_client(&g_wflink_ctx.coapClient);
							break;
					}
				}
				else
				{
					switch(errcode)
					{
						case CEC_SUCCESS:
							update_token(data);
							enqueue_state_machine(st, STATE_SYNC);
							break;
						case CEC_LOGINPWD_NOMATCH:
						case CEC_DEVNONEXISTENT:
						case CEC_ARGUMENT_INCOMPLETED:
						case CEC_INTERNAL:
							timer_add(g_wflink_ctx.htimer, RETRANSMISSION_INTERVAL_SEC * 1000, 0, error_retransmission, (void *)STATE_CONN);
							break;
						case CEC_DEVDELETED:
							stop_coap_client(&g_wflink_ctx.coapClient);
							_cfg_func_setObject("activiated", "0");
							break;
						default:
							break;
					}
				}
				break;
			case STATE_SYNC:
				switch(errcode)
				{
					case CEC_SUCCESS:
					case CEC_ARGUMENT_INCOMPLETED:
					case CEC_INTERNAL:
						enqueue_state_machine(st, STATE_HEARTBT);
						break;
					default:
						break;
				}
				break;
			case STATE_HEARTBT:
				// heartbeat | refresh response
				switch(errcode)
				{
					case CEC_SUCCESS:
						update_token(data);
						break;
					case CEC_ACCESSTOKEN_EXPIRE:
					case CEC_REFRESHTOKEN_EXPIRE:
					case CEC_OPTIONTOKEN_MISS:
					case CEC_ARGUMENT_INCOMPLETED:
					case CEC_INTERNAL:
						stop_coap_client_and_reinit();
						start_relogin();
						break;
					default:
						break;
				}
				break;
			case STATE_ACTIVATE:
				switch(errcode)
				{
					case CEC_SUCCESS:
						cJSON_GetStringByKey(data, "devId", tmpstr);
						if(tmpstr)
						{
							// set devId from handle_verifycode into here
							_cfg_func_setObject("devId", tmpstr);
							//_cfg_func_getObject("devId", buffer, sizeof(buffer));
							//if(!strncmp(tmpstr, buffer, strlen(tmpstr)))
							//{
								_cfg_func_setObject("activiated", "1");
								free(tmpstr);
								tmpstr = NULL;
								cJSON_GetStringByKey(data, "secret", tmpstr);
								if(tmpstr)
								{
									_cfg_func_setObject("secret", tmpstr);
									free(tmpstr);
									tmpstr = NULL;
								}
								enqueue_state_machine(st, STATE_CONN);
							//}
							//else
							//{
							//	DBGPRINT(DEBUG_ERROR, "devId:%s not match!!!\n", tmpstr);
							//	free(tmpstr);
							//}
						}
						break;
					default:
						break;
				}
				break;
			default:
				DBGPRINT(DEBUG_ERROR, "state %d is out of State machine!!!\n", state);
				break;
		}
	}
	else
	{
		DBGPRINT(DEBUG_ERROR, "no errcode in response!!!\n");
	}
	cJSON_Delete(data);
	return 0;
json_err:
	DBGPRINT(DEBUG_ERROR, "body is not json format or value type error!!!\n");
	return 0;
}

int stop_coap_client_and_reinit(void)
{
	stop_coap_client(&g_wflink_ctx.coapClient);
	if(-1 != data_in_memory.heartbeat_tid)
	{
		timer_del(g_wflink_ctx.htimer, data_in_memory.heartbeat_tid);
		data_in_memory.heartbeat_tid = -1;
	}
	if(-1 != data_in_memory.refreshtoken_tid)
	{
		timer_del(g_wflink_ctx.htimer, data_in_memory.refreshtoken_tid);
		data_in_memory.refreshtoken_tid = -1;
	}
	return 0;
}
int start_relogin(void)
{
	return enqueue_state_machine(st, STATE_CONN);
}
