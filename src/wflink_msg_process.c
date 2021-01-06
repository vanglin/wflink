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
#include <sys/sysinfo.h>

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

int get_wandiagnose(virtual_construct_t*construct,void*req,void*resp)
{
	DBGPRINT(DEBUG_INFO, "get_HostInfo start !!!\n");
	DBGPRINT(DEBUG_INFO, "get_wandiagnose start !!!\n");
	char buffer[125] = {0};
	char tmp[125] = {0};
	char slen[32] = {0};
	cJSON *jsonSend = NULL;
	char *tx_body = NULL;
	char nodeName[32] = {0};
	unsigned short coaphead = COAP_OPT_ACCESS_TOKEN_ID;
	
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
	if ( 0 == tcapi_get("waninfo_Common", "EthernetState", buffer)&& 0 != buffer[0])
	{
		if (!strcmp(buffer, "up"))
		{
			cJSON_AddStringToObject(jsonSend, "StatusCode", "Connected");	
			cJSON_AddStringToObject(jsonSend, "ErrReason", "Connected");	
		}
		else
		{
			cJSON_AddStringToObject(jsonSend, "StatusCode", "DisConnected");	
			cJSON_AddStringToObject(jsonSend, "ErrReason", "DisConnected");	
		}
	}
	
	bzero(buffer, sizeof(buffer));
	if ( 0 == tcapi_get("waninfo_Common", "CurAPMode", buffer)&& 0 != buffer[0])
	{
		if ( 0 == strcmp(buffer, "Bridge") )
		{		
			cJSON_AddStringToObject(jsonSend, "WanType", "Bridged");
			cJSON_AddBoolToObject(jsonSend, "HasInternetWan", 1);
		}
		else if( 0 == strcmp(buffer, "Route"))
		{
			bzero(tmp, sizeof(tmp));
			tcapi_get("waninfo_Common", "CycleValue_9", tmp);
			if ( 0 == strcmp(tmp, "DHCP") || 0 == strcmp(tmp, "Static"))
			{		
				cJSON_AddStringToObject(jsonSend, "WanType", "IP_Routed"); 				
				cJSON_AddBoolToObject(jsonSend, "HasInternetWan", 1);
			}
			else if( 0 == strcmp(tmp, "PPPoE"))
			{
				cJSON_AddStringToObject(jsonSend, "WanType", "PPP_Routed");
				cJSON_AddBoolToObject(jsonSend, "HasInternetWan", 1);
			}
			else
			{
				cJSON_AddStringToObject(jsonSend, "WanType", "IP_Routed");				
				cJSON_AddBoolToObject(jsonSend, "HasInternetWan", 1);
			}
 		}
	}
	
	if ( 0 == tcapi_get("waninfo_entry0", "Status", buffer)&& 0 != buffer[0])
	{
		if (!strcmp(buffer, "up"))
		{
			cJSON_AddStringToObject(jsonSend, "Status", "Connected");
		}
		else
		{
			cJSON_AddStringToObject(jsonSend, "Status", "DisConnected");
		}
	}

	bzero(buffer, sizeof(buffer));
	if ( 0 == tcapi_get("waninfo_entry0", "IP", buffer)&& 0 != buffer[0])
	{
		cJSON_AddStringToObject(jsonSend, "ExternalIPAddress", buffer);
	}

	bzero(buffer, sizeof(buffer));
	if ( 0 == tcapi_get("waninfo_entry0", "hwaddr", buffer)&& 0 != buffer[0])
	{
		cJSON_AddStringToObject(jsonSend, "MACAddress", buffer);
	}
	
	tx_body = cJSON_PrintUnformatted(jsonSend);
	cJSON_Delete(jsonSend);	
	if(VCONS_COAP == construct->type)
	{
		construct->set_header(resp, &coaphead, data_in_memory.accessToken);
		coap_set_headrespkey(construct, req, resp );
	}
	else if(VCONS_HTTP == construct->type)
	{
		construct->set_header(resp, "Content-Type", MIME_TYPE_JSON);
		construct->set_header(resp, "Content-Length", intIntoString(strlen(tx_body), slen, sizeof(slen)));
	}
	if(tx_body)
	{
		DBGPRINT(DEBUG_INFO, "tx_body:%s !!!\n",tx_body);
		construct->set_body(resp, tx_body, strlen(tx_body));
		free(tx_body);
	}
	return 0;
}


int get_HostInfo(virtual_construct_t*construct,void*req,void*resp)
{
	DBGPRINT(DEBUG_INFO, "get_HostInfo start !!!\n");
	char buffer[125] = {0};
	char deviceMac[16];
	char deviceSn[64];
	char slen[32] = {0};
	cJSON *jsonsta = NULL,*jsonArray = NULL;
	char *tx_body = NULL;
	char buf[32] = {0};
	char nodeName[32] = {0};
	char uplinkType[20] = {0}, uplinkRadio[20] = {0};
	char tmpMac[32] = {0} ;
	double RxRate_rt = 0, TxRate_rt = 0;
	char tmpbuf[16] = {0};
	int i = 0 , count = 0;
	unsigned short coaphead = COAP_OPT_ACCESS_TOKEN_ID;
	
	if(VCONS_COAP == construct->type)
	{
		construct->set_code(resp, 201);
	}
	else if(VCONS_HTTP == construct->type)
	{
		construct->set_code(resp, 200);	
	}

	jsonArray = cJSON_CreateArray();

	for(i = 0; i < 64; i++)
	{
		memset(nodeName, 0, sizeof(nodeName));
		snprintf(nodeName, sizeof(nodeName), "LANHost2_Entry%d", i);
			
		memset(buf, 0, sizeof(buf));
		tcapi_get(nodeName, "Active", buf);
		
		printf("%s %d  nodeName:%s  buf:%s \n\n",__FUNCTION__,__LINE__,nodeName,buf);
		if(atoi(buf) == 1)
		{
			memset(buf, 0, sizeof(buf));
			tcapi_get(nodeName,"IP",buf);
			if((strcasecmp(buf,"192.168.1.1") == 0) || (buf[0] == '\0'))
			{
				printf("%s %d gate way ip,ignore.  nodeName:%s\n",__FUNCTION__,__LINE__,nodeName);
				continue;
			}
			
			jsonsta = cJSON_CreateObject();
		
			cJSON_AddBoolToObject(jsonsta, "Active", atoi(buf));
			cJSON_AddBoolToObject(jsonsta, "Active46", atoi(buf));
			
			cJSON_AddStringToObject(jsonsta, "ID", nodeName);
		
			memset(buf, 0, sizeof(buf));
			tcapi_get(nodeName, "MAC", buf);
			if(buf[0] != '\0')
			{			
				tcapi_get("WanInfo_Common", "CurAPMode", uplinkType);
				if( !strcmp(uplinkType, "APClient") )
				{
					tcapi_get("APCli_Common", "currentRadio", uplinkRadio);
					if( !strcmp(uplinkRadio, "1") )
					{
						tcapi_get("Info_apclii0", "hwaddr", tmpMac);
					}
					else
					{
						tcapi_get("Info_apcli0", "hwaddr", tmpMac);
					}
					
					if( '\0' != tmpMac[0] )
					{
						cJSON_AddStringToObject(jsonsta, "MACAddress", tmpMac);
					}
				}
				else
					stringToCapital(buf);
					//sprintf(devMac,"%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x",buf[0], buf[1],buf[2], buf[3], buf[4], buf[5]);
					cJSON_AddStringToObject(jsonsta, "MACAddress", buf);
			}
			
			memset(buf, 0, sizeof(buf));
			tcapi_get(nodeName, "IP", buf);
			cJSON_AddStringToObject(jsonsta, "IPAddress", buf);

					
			memset(buf, 0, sizeof(buf));
			tcapi_get(nodeName, "HostName", buf);
			if( strlen(buf) > 0 )
			{
				printf("\n HostName-buf %s ,strlen(buf):%d .\n", buf,strlen(buf));
				cJSON_AddStringToObject(jsonsta, "HostName", buf);
				cJSON_AddStringToObject(jsonsta, "AddressSource", "DHCP"); 		
			}
			else
			{
				printf( "2%s %d.\n", __FUNCTION__,__LINE__);
				tcapi_get(nodeName, "MAC", buf);					
				stringToCapital(buf);
				cJSON_AddStringToObject(jsonsta, "HostName", buf);
				cJSON_AddStringToObject(jsonsta, "AddressSource", "Static");			
			}

			// zzx ??? 
			cJSON_AddStringToObject(jsonsta, "IconType", "Android");			

			cJSON_AddStringToObject(jsonsta, "DevBrands", "NOKIA");			
					
			memset(buf, 0, sizeof(buf));
			tcapi_get(nodeName, "RxRate_rt", buf);
			RxRate_rt = ((atoi(buf) * 8.0)/1024);
			if( RxRate_rt == 0 )
				snprintf(tmpbuf, sizeof(tmpbuf), "0");
			else
				snprintf(tmpbuf, sizeof(tmpbuf), "%0.4f", RxRate_rt);		
			cJSON_AddNumberToObject(jsonsta, "DownRate", atoi(tmpbuf));// kbp/s		
						
			memset(buf, 0, sizeof(buf));
			tcapi_get(nodeName, "TxRate_rt", buf);
			TxRate_rt = ((atoi(buf) * 8.0)/1024);
			if( TxRate_rt == 0 )
				snprintf(tmpbuf, sizeof(tmpbuf), "0");
			else
				snprintf(tmpbuf, sizeof(tmpbuf), "%0.4f", TxRate_rt);
			cJSON_AddNumberToObject(jsonsta, "UpRate", atoi(tmpbuf));// kbp/s	
			
			cJSON_AddItemToArray(jsonArray,jsonsta);	
			
			//cJSON_Delete(jsonsta);//不可以在此释放
		}
	}

	tx_body = cJSON_PrintUnformatted(jsonArray);
	cJSON_Delete(jsonArray);	
	if(VCONS_COAP == construct->type)
	{
		construct->set_header(resp, &coaphead, data_in_memory.accessToken);
		coap_set_headrespkey(construct, req, resp );
	}
	else if(VCONS_HTTP == construct->type)
	{
		construct->set_header(resp, "Content-Type", MIME_TYPE_JSON);
		construct->set_header(resp, "Content-Length", intIntoString(strlen(tx_body), slen, sizeof(slen)));
	}
	if(tx_body)
	{
		DBGPRINT(DEBUG_INFO, "tx_body:%s !!!\n",tx_body);
		construct->set_body(resp, tx_body, strlen(tx_body));
		free(tx_body);
	}
	
	DBGPRINT(DEBUG_INFO, "get_HostInfo end !!!\n");
	return 0;
}

int handle_change_devicename(virtual_construct_t*construct,void*req,void*resp)
{
	char *body = NULL, *ID = NULL, *ActualName = NULL, *tx_body = NULL;
	char slen[32] = {0};
	int body_len = 0;
	cJSON *data = NULL, *jsonSend = NULL;
	int errcode = 0 ;
	
	if(VCONS_COAP == construct->type)
	{
		construct->set_code(resp, 201);
	}
	else if(VCONS_HTTP == construct->type)
	{
		construct->set_code(resp, 200);	
		construct->set_header(resp, "Content-Type", MIME_TYPE_JSON);
	}

	construct->get_body(req, &body, &body_len);
	if(body)
	{
		if(data = cJSON_Parse(body))
		{
			cJSON_GetStringByKey(data, "ID", ID);
			cJSON_GetStringByKey(data, "ActualName", ActualName);
			if(ID && ActualName)
			{
				tcapi_set(ID, "HostName", ActualName);			
				tcapi_save();
			}
			else
			{
				errcode = -1 ;			
			}
		}
		cJSON_Delete(data);
		WF_FREE(ID);
		WF_FREE(ActualName);
	}

	jsonSend = cJSON_CreateObject();
	cJSON_AddNumberToObject(jsonSend, "errcode", errcode);
	tx_body = cJSON_PrintUnformatted(jsonSend);
	cJSON_Delete(jsonSend);
	if(tx_body)
	{
		construct->set_header(resp, "Content-Length", intIntoString(strlen(tx_body), slen, sizeof(slen)));
		construct->set_body(resp, tx_body, strlen(tx_body));	
		free(tx_body);
	}
	return 0;
}

int get_deviceinfo(virtual_construct_t*construct,void*req,void*resp)
{
	DBGPRINT(DEBUG_INFO, "get_deviceinfo start !!!\n");
	struct sysinfo info;
	cJSON *jsonSend = NULL;
	char *tx_body = NULL;
	char buffer[64] = {0};
	char slen[32] = {0};
	unsigned short coaphead = COAP_OPT_ACCESS_TOKEN_ID;

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
	if ( 0 == tcapi_get("DeviceInfo_devParaStatic", "ModelName", buffer)&& 0 != buffer[0])
		cJSON_AddStringToObject(jsonSend, "DeviceName", buffer);

	bzero(buffer, sizeof(buffer));
	if ( 0 == tcapi_get("DeviceInfo_devParaDynamic", "SerialNum", buffer)&& 0 != buffer[0])
		cJSON_AddStringToObject(jsonSend, "SerialNumber", buffer);
	
	bzero(buffer, sizeof(buffer));	
	if ( 0 == tcapi_get("DeviceInfo_devParaDynamic","ManufacturerOUI",buffer)&& 0 != buffer[0])
		cJSON_AddStringToObject(jsonSend, "ManufacturerOUI", buffer);
	
	bzero(buffer, sizeof(buffer));
	if ( 0 == tcapi_get("DeviceInfo_devParaStatic", "CustomerSWVersion", buffer)&& 0 != buffer[0])
		cJSON_AddStringToObject(jsonSend, "SoftwareVersion", buffer);
	
	bzero(buffer, sizeof(buffer));
	if ( 0 == tcapi_get("DeviceInfo_devParaStatic", "CustomerHWVersion", buffer)&& 0 != buffer[0])
		cJSON_AddStringToObject(jsonSend, "HardwareVersion", buffer);

	sysinfo(&info);
	cJSON_AddNumberToObject(jsonSend, "UpTime", info.uptime);

	bzero(buffer, sizeof(buffer));
	if ( 0 == tcapi_get("Info_sysdevice", "CpuUsage", buffer)&& 0 != buffer[0])
		cJSON_AddNumberToObject(jsonSend, "CPUUsage", atoi(buffer));
	
	bzero(buffer, sizeof(buffer));
	if ( 0 == tcapi_get("Info_sysdevice", "MemoryTotal", buffer)&& 0 != buffer[0])
		cJSON_AddNumberToObject(jsonSend, "MemTotal", atoi(buffer));
	
	bzero(buffer, sizeof(buffer));
	if ( 0 == tcapi_get("Info_sysdevice", "MemoryUsage", buffer)&& 0 != buffer[0])
		cJSON_AddNumberToObject(jsonSend, "MemFree", atoi(buffer));

	bzero(buffer, sizeof(buffer));
	if ( 0 == tcapi_get("DeviceInfo_devParaStatic", "Manufacturer", buffer)&& 0 != buffer[0])
		cJSON_AddStringToObject(jsonSend, "Manufacturer", buffer);

	cJSON_AddStringToObject(jsonSend, "ChipModel", "MTK"); 		

	tx_body = cJSON_PrintUnformatted(jsonSend);
	cJSON_Delete(jsonSend);
	if(VCONS_COAP == construct->type)
	{
		construct->set_header(resp, &coaphead, data_in_memory.accessToken);
		coap_set_headrespkey(construct, req, resp );
	}
	else if(VCONS_HTTP == construct->type)
	{
		construct->set_header(resp, "Content-Type", MIME_TYPE_JSON);
		construct->set_header(resp, "Content-Length", intIntoString(strlen(tx_body), slen, sizeof(slen)));
	}
	if(tx_body)
	{
		DBGPRINT(DEBUG_INFO, "tx_body:%s !!!\n",tx_body);
		construct->set_body(resp, tx_body, strlen(tx_body));
		free(tx_body);
	}	
	return 0;
}

int get_lan_host(virtual_construct_t*construct,void*req,void*resp)
{
	char buffer[125] = {0};
	cJSON *jsonSend = NULL;
	char *tx_body = NULL;
	char nodeName[32] = {0};
	char MACAddress[32] = {0};
	char slen[32] = {0};
	int ret = -1;
	unsigned short coaphead = COAP_OPT_ACCESS_TOKEN_ID;

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
	
	if(VCONS_COAP == construct->type)
	{
		construct->set_header(resp, &coaphead, data_in_memory.accessToken);
		coap_set_headrespkey(construct, req, resp );
	}
	else if(VCONS_HTTP == construct->type)
	{
		construct->set_header(resp, "Content-Type", MIME_TYPE_JSON);
		construct->set_header(resp, "Content-Length", intIntoString(strlen(tx_body), slen, sizeof(slen)));
	}
	
	if(tx_body)
	{
		DBGPRINT(DEBUG_INFO, "tx_body:%s !!!\n",tx_body);
		construct->set_body(resp, tx_body, strlen(tx_body));
		free(tx_body);
	}
	return 0;
}

int handle_qosclass_host(virtual_construct_t*construct,void*req,void*resp)
{
	char *body = NULL, *QosclassID= NULL, *ActualName = NULL, *tx_body = NULL;
	char *DeviceDownRateEnable= NULL, *ClassQueue = NULL, *DeviceMaxDownLoadRate = NULL;
	char *MACAddress= NULL, *ID = NULL, *DeviceMaxUpLoadRate = NULL;
	char buffer[125] = {0};	
	char slen[32] = {0};
	int body_len = 0;
	cJSON *data = NULL, *jsonSend = NULL;
	int errcode = 0 ;
	char node_name[64] = {0};
	char entry_id[8] = {0};
	int entry_num = 0;
	unsigned short coaphead = COAP_OPT_ACCESS_TOKEN_ID;
	
	printf("\n\n zzx111  printf  req =================>>>>> ");
    coap_show_pdu(LOG_INFO, (coap_pdu_t *)req);
	printf("\n ");

	
	if(VCONS_COAP == construct->type)
	{
		construct->set_code(resp, 201);
	}
	else if(VCONS_HTTP == construct->type)
	{
		construct->set_code(resp, 200);	
		construct->set_header(resp, "Content-Type", MIME_TYPE_JSON);
	}

	construct->get_body(req, &body, &body_len);
	if(body)
	{
		if(data = cJSON_Parse(body))
		{
			cJSON_GetStringByKey(data, "QosclassID", QosclassID);
			if(QosclassID)//QosclassID is not NULL , update old
			{
				cJSON_GetStringByKey(data, "MACAddress", MACAddress);
				cJSON_GetStringByKey(data, "ID", ID);
				if(MACAddress && ID)
				{
					tcapi_get(ID, "MACAddress", buffer);
					if( !strcmp(buffer,MACAddress))
					{
						cJSON_GetIntByKey(data, "DeviceMaxDownLoadRate", DeviceMaxDownLoadRate);
						cJSON_GetIntByKey(data, "DeviceMaxUpLoadRate", DeviceMaxUpLoadRate);
						tcapi_set(ID, "upRate", DeviceMaxUpLoadRate);			
						tcapi_set(ID, "downRate", DeviceMaxDownLoadRate);							
						tcapi_save();
						tcapi_commit("MaxBandWidth_Common");
					}
				}
				else
				{
					errcode = -1 ;			
				}
			}
			else // QosclassID is NULL , create qos
			{
				cJSON_GetStringByKey(data, "ID", ID);
				if( strlen(ID) > 14)
				{
					strcpy(entry_id ,ID);
					entry_num = atoi(entry_id);					
					snprintf(node_name, sizeof(node_name), "MaxBandWidth_Common");	
					bzero(buffer, sizeof(buffer));
					tcapi_get(node_name, "num", buffer);

					if( entry_num > atoi(buffer) )
					{
						tcapi_set(node_name, "num", itoa(atoi(buffer)+1));
						cJSON_GetStringByKey(data, "DeviceMaxDownLoadRate", DeviceMaxDownLoadRate);
						cJSON_GetStringByKey(data, "DeviceMaxUpLoadRate", DeviceMaxUpLoadRate);
						cJSON_GetStringByKey(data, "MACAddress", MACAddress);
						tcapi_set(ID, "upRate", DeviceMaxUpLoadRate);			
						tcapi_set(ID, "downRate", DeviceMaxDownLoadRate);							
						tcapi_set(ID, "mac", MACAddress);				
						tcapi_save();			
						tcapi_commit("MaxBandWidth_Common");
					}
					else
					{
						errcode = -1 ;			
					}
				}
				else
				{
					errcode = -1 ;			
				}
				

			}
		}
		cJSON_Delete(data);
		WF_FREE(QosclassID);
		WF_FREE(MACAddress);
		WF_FREE(ID);
		WF_FREE(DeviceMaxDownLoadRate);
		WF_FREE(DeviceMaxUpLoadRate);
		WF_FREE(DeviceDownRateEnable);
	}

	jsonSend = cJSON_CreateObject();
	cJSON_AddNumberToObject(jsonSend, "errcode", errcode);
	tx_body = cJSON_PrintUnformatted(jsonSend);
	cJSON_Delete(jsonSend);

	if(VCONS_COAP == construct->type)
	{
		construct->set_header(resp, &coaphead, data_in_memory.accessToken);
		coap_set_headrespkey(construct, req, resp );
	}
	else if(VCONS_HTTP == construct->type)
	{
		construct->set_header(resp, "Content-Type", MIME_TYPE_JSON);
		construct->set_header(resp, "Content-Length", intIntoString(strlen(tx_body), slen, sizeof(slen)));
	}
	if(tx_body)
	{
		construct->set_body(resp, tx_body, strlen(tx_body));
		free(tx_body);
	}
	return 0;
}

int get_WlanBasic(virtual_construct_t*construct,void*req,void*resp)
{
	char buffer[64] = {0};
	char buffer1[64] = {0};
	char buffer2[64] = {0};
	char WifiSsidIndex[32] = {0};
	char nodeName[32] = {0},attrName[32] = {0},SecurityMode[32] = {0};
	char  TxPower[4] = {0},  powerlevel[4] = {0};
	cJSON *jsonSend = NULL,*WifiConfigArray = NULL,*WifiConfig24g = NULL,*WifiConfig5g = NULL;
	int DbhoEnable = 0;
	char *tx_body = NULL,*DeviceDownRateEnable= NULL, *ClassQueue = NULL, *DeviceMaxDownLoadRate = NULL;
	char slen[32] = {0};
	unsigned short coaphead = COAP_OPT_ACCESS_TOKEN_ID;

	if(VCONS_COAP == construct->type)
	{ 
		construct->set_code(resp, 201);
	}
	else if(VCONS_HTTP == construct->type)
	{
		construct->set_code(resp, 200);	
	}

	jsonSend = cJSON_CreateObject();

	// zzx ???
	bzero(buffer, sizeof(buffer));
	if ( 0 == tcapi_get("WLan11ac_common", "DbhoEnable", buffer)&& 0 != buffer[0])
	{
		cJSON_AddBoolToObject(jsonSend, "DbhoEnable",atoi(buffer));
		DbhoEnable = atoi(buffer);
	}
	else
		cJSON_AddBoolToObject(jsonSend, "DbhoEnable",DbhoEnable);
		

	WifiConfigArray = cJSON_CreateArray();
	cJSON_AddItemToObject(jsonSend,"WifiConfig",WifiConfigArray);

	//2.4g WifiConfig
	WifiConfig24g = cJSON_CreateObject();
	cJSON_AddItemToArray(WifiConfigArray,WifiConfig24g);

	bzero(WifiSsidIndex, sizeof(WifiSsidIndex));
	if ( 0 == tcapi_get("WebCurSet_Entry", "wlan_id", WifiSsidIndex)&& 0 != WifiSsidIndex[0])
	{
		memset(nodeName, 0, sizeof(nodeName));
		snprintf(nodeName, sizeof(nodeName), "WLan_Entry%d", atoi(WifiSsidIndex));
	}
	
	bzero(buffer, sizeof(buffer));
	if ( 0 == tcapi_get(nodeName, "WMM", buffer)&& 0 != buffer[0])
		cJSON_AddBoolToObject(WifiConfig24g, "WMMEnable", atoi(buffer));
	
	bzero(buffer1, sizeof(buffer1));
	tcapi_get(nodeName, "AuthMode", buffer1);
	DBGPRINT(DEBUG_INFO,"[%s:%d]:buffer1:%s	!!!===========>\n",__FUNCTION__,__LINE__,buffer1);
	if( !strcmp(buffer1, "OPEN") )
	{
		snprintf(SecurityMode, sizeof(SecurityMode), "None");
		cJSON_AddStringToObject(WifiConfig24g, "BeaconType", "None");			
	}
	else if( !strcmp(buffer1, "WEP-64Bits") )
	{
		snprintf(SecurityMode, sizeof(SecurityMode), "WEP-64");
		cJSON_AddStringToObject(WifiConfig24g, "BeaconType", "WEP");			
	}
	else if( !strcmp(buffer1, "WEP-128Bits") )
	{
		snprintf(SecurityMode, sizeof(SecurityMode), "WEP-128");
		cJSON_AddStringToObject(WifiConfig24g, "BeaconType", "WEP");			
	}
	else if( !strcmp(buffer1, "WPAPSK") )
	{
		snprintf(SecurityMode, sizeof(SecurityMode), "WPA-Personal");
		cJSON_AddStringToObject(WifiConfig24g, "BeaconType", "WPA");			
	}
	else if( !strcmp(buffer1, "WPA2PSK") )
	{
		snprintf(SecurityMode, sizeof(SecurityMode), "WPA2-Personal");
		cJSON_AddStringToObject(WifiConfig24g, "BeaconType", "11i");			
	}
	else if( !strcmp(buffer1, "WPAPSKWPA2PSK") )
	{
		snprintf(SecurityMode, sizeof(SecurityMode), "MIXED-WPAPSK2");
		cJSON_AddStringToObject(WifiConfig24g, "BeaconType", "WPAand11i");			
	}
	bzero(buffer, sizeof(buffer));
	bzero(buffer1, sizeof(buffer1));
	if( strstr(SecurityMode, "WEP-") )
	{
		tcapi_get(nodeName, "DefaultKeyID", buffer1);
		snprintf(attrName, sizeof(attrName), "Key%dStr", atoi(buffer1));
		tcapi_get(nodeName, attrName, buffer);
	}
	else if( strstr(SecurityMode, "WPA") )
	{
		tcapi_get(nodeName, "WPAPSK", buffer);
	}
	cJSON_AddStringToObject(WifiConfig24g, "WpaPreSharedKey", buffer);
	

	bzero(TxPower, sizeof(TxPower));
	bzero(powerlevel, sizeof(powerlevel));
	if ( 0 == tcapi_get("WLan_Common", "TxPowerLevel" , TxPower)&& 0 != TxPower[0])
	switch(atoi(TxPower))
	{
		case 5:
		case 10:
			strncpy(powerlevel,"20",sizeof(powerlevel)-1);
			break;
		case 4:
		case 25:
			strncpy(powerlevel,"40",sizeof(powerlevel)-1);
			break;
		case 3:
		case 50:
			strncpy(powerlevel,"60",sizeof(powerlevel)-1);
			break;
		case 2:
		case 80:
			strncpy(powerlevel,"80",sizeof(powerlevel)-1);
			break;
		case 1:
		case 100:
			strncpy(powerlevel,"100",sizeof(powerlevel)-1);
			break;
		default:
			break;
	}
	strncpy(TxPower, powerlevel, sizeof(TxPower) - 1);
	cJSON_AddNumberToObject(WifiConfig24g, "TransmitPower", atoi(TxPower));


	bzero(buffer, sizeof(buffer));
	if ( 0 == tcapi_get(nodeName, "HT_MCS" , buffer)&& 0 != buffer[0])
	{
		if( !strcmp(buffer,"33"))
		{
			cJSON_AddStringToObject(WifiConfig24g, "X_Wlan11NHtMcs", "Auto");
		}
		else
		{
			cJSON_AddStringToObject(WifiConfig24g, "X_Wlan11NHtMcs", buffer);	
		}
	}

	bzero(buffer, sizeof(buffer));
	if ( 0 == tcapi_get(nodeName, "EncrypType" , buffer)&& 0 != buffer[0])
		cJSON_AddStringToObject(WifiConfig24g, "MixedEncryptionModes", buffer);
	
	bzero(buffer, sizeof(buffer));
	if ( 0 == tcapi_get("WLan_Common", "WirelessMode" , buffer)&& 0 != buffer[0])
	{
		if( !strcmp(buffer,"1"))
		{
			cJSON_AddStringToObject(WifiConfig24g, "WlanStandard", "b");
		}
		else if(!strcmp(buffer,"4"))
		{
			cJSON_AddStringToObject(WifiConfig24g, "WlanStandard", "g");	
		}
		else if(!strcmp(buffer,"6"))
		{
			cJSON_AddStringToObject(WifiConfig24g, "WlanStandard", "n");
			bzero(buffer, sizeof(buffer));
			bzero(buffer1, sizeof(buffer1));
			bzero(buffer2, sizeof(buffer2));
			tcapi_get("WLan_Common", "HT_BW" , buffer);
			tcapi_get("WLan_Common", "HT_EXTCHA" , buffer1);
			if(!strcmp(buffer,"0") && !strcmp(buffer1,"0"))
			{
				cJSON_AddStringToObject(WifiConfig24g, "X_Wlan11NBWControl", "20");					
			}
			else 
			{
				cJSON_AddStringToObject(WifiConfig24g, "X_Wlan11NBWControl", "20_40"); 					
			}
		}	
		else if(!strcmp(buffer,"9"))
		{
			cJSON_AddStringToObject(WifiConfig24g, "WlanStandard", "b/g/n");	
		}	
	}	

	bzero(buffer, sizeof(buffer));
	if ( 0 == tcapi_get("WLan_Common", "APOn" , buffer)&& 0 != buffer[0])
		cJSON_AddBoolToObject(WifiConfig24g, "WifiEnable", atoi(buffer));

	cJSON_AddStringToObject(WifiConfig24g, "FrequencyBand", "2.4GHz");

	cJSON_AddNumberToObject(WifiConfig24g, "WifiSsidIndex", atoi(WifiSsidIndex));	


	bzero(buffer, sizeof(buffer));
	if ( 0 == tcapi_get(nodeName, "HideSSID" , buffer)&& 0 != buffer[0])
		cJSON_AddBoolToObject(WifiConfig24g, "WifiHideBroadcast", atoi(buffer));
	
	bzero(buffer, sizeof(buffer));
	if ( 0 == tcapi_get(nodeName, "SSID" , buffer)&& 0 != buffer[0])
		cJSON_AddStringToObject(WifiConfig24g, "WifiSsid", buffer);

	bzero(buffer, sizeof(buffer));
	if ( 0 == tcapi_get("WLan_Common", "HT_GI" , buffer)&& 0 != buffer[0])
	{
		if( !strcmp(buffer,"0"))
		{
			cJSON_AddStringToObject(WifiConfig24g, "X_Wlan11NGIControl", "long");			
		}
		else if(!strcmp(buffer,"1"))
		{
			cJSON_AddStringToObject(WifiConfig24g, "X_Wlan11NGIControl", "short");	
		}
	}

	// zzx ???
	cJSON_AddBoolToObject(WifiConfig24g, "X_WlanIsolateControl", 1);

	bzero(buffer, sizeof(buffer));
	if ( 0 == tcapi_get("Info_WLan", "CurrentChannel", buffer)&& 0 != buffer[0])
		cJSON_AddNumberToObject(WifiConfig24g, "Channel", atoi(buffer));

	bzero(buffer, sizeof(buffer));
	if ( 0 == tcapi_get("WLan_Common", "MaxStaNum", buffer)&& 0 != buffer[0])
		cJSON_AddNumberToObject(WifiConfig24g, "X_AssociateDeviceNum", atoi(buffer));

	bzero(buffer, sizeof(buffer));
	if ( 0 == tcapi_get("WLan_Common", "HT_RATE", buffer)&& 0 != buffer[0])
	{
		if( !strcmp(buffer,"Auto"))
		{
			cJSON_AddStringToObject(WifiConfig24g, "MaxBitRate", "0");	
		}
		else
		{
			cJSON_AddStringToObject(WifiConfig24g, "MaxBitRate", buffer);		
		}
	}

	//5g WifiConfig	
	if( 1 )
	{
		WifiConfig5g = cJSON_CreateObject();
		cJSON_AddItemToArray(WifiConfigArray,WifiConfig5g);	

		bzero(WifiSsidIndex, sizeof(WifiSsidIndex));
		if ( 0 == tcapi_get("WebCurSet_Entry", "wlan_ac_id", WifiSsidIndex)&& 0 != WifiSsidIndex[0])
		{
			memset(nodeName, 0, sizeof(nodeName));
			snprintf(nodeName, sizeof(nodeName), "WLan11ac_Entry%d", atoi(WifiSsidIndex));
		}

		bzero(buffer, sizeof(buffer));
		if ( 0 == tcapi_get(nodeName, "WMM", buffer)&& 0 != buffer[0])
			cJSON_AddBoolToObject(WifiConfig5g, "WMMEnable", atoi(buffer));

		bzero(buffer1, sizeof(buffer1));
		tcapi_get(nodeName, "AuthMode", buffer1);
		DBGPRINT(DEBUG_INFO,"[%s:%d]:buffer1:%s !!!===========>\n",__FUNCTION__,__LINE__,buffer1);
		if( !strcmp(buffer1, "OPEN") )
		{
			snprintf(SecurityMode, sizeof(SecurityMode), "None");
			cJSON_AddStringToObject(WifiConfig5g, "BeaconType", "None");			
		}
		else if( !strcmp(buffer1, "WEP-64Bits") )
		{
			snprintf(SecurityMode, sizeof(SecurityMode), "WEP-64");
			cJSON_AddStringToObject(WifiConfig5g, "BeaconType", "WEP");			
		}
		else if( !strcmp(buffer1, "WEP-128Bits") )
		{
			snprintf(SecurityMode, sizeof(SecurityMode), "WEP-128");
			cJSON_AddStringToObject(WifiConfig5g, "BeaconType", "WEP");			
		}
		else if( !strcmp(buffer1, "WPAPSK") )
		{
			snprintf(SecurityMode, sizeof(SecurityMode), "WPA-Personal");
			cJSON_AddStringToObject(WifiConfig5g, "BeaconType", "WPA");			
		}
		else if( !strcmp(buffer1, "WPA2PSK") )
		{
			snprintf(SecurityMode, sizeof(SecurityMode), "WPA2-Personal");
			cJSON_AddStringToObject(WifiConfig5g, "BeaconType", "11i");			
		}
		else if( !strcmp(buffer1, "WPAPSKWPA2PSK") )
		{
			snprintf(SecurityMode, sizeof(SecurityMode), "MIXED-WPAPSK2");
			cJSON_AddStringToObject(WifiConfig5g, "BeaconType", "WPAand11i");			
		}
		bzero(buffer, sizeof(buffer));
		bzero(buffer1, sizeof(buffer1));
		if( strstr(SecurityMode, "WEP-") )
		{
			tcapi_get(nodeName, "DefaultKeyID", buffer1);
			snprintf(attrName, sizeof(attrName), "Key%dStr", atoi(buffer1));
			tcapi_get(nodeName, attrName, buffer);
		}
		else if( strstr(SecurityMode, "WPA") )
		{
			tcapi_get(nodeName, "WPAPSK", buffer);
		}
		cJSON_AddStringToObject(WifiConfig5g, "WpaPreSharedKey", buffer);
		
		bzero(TxPower, sizeof(TxPower));
		bzero(powerlevel, sizeof(powerlevel));
		if ( 0 == tcapi_get("WLan11ac_Common", "TxPower" , TxPower)&& 0 != TxPower[0])
		switch(atoi(TxPower))
		{
			case 5:
			case 10:
				strncpy(powerlevel,"20",sizeof(powerlevel)-1);
				break;
			case 4:
			case 25:
				strncpy(powerlevel,"40",sizeof(powerlevel)-1);
				break;
			case 3:
			case 50:
				strncpy(powerlevel,"60",sizeof(powerlevel)-1);
				break;
			case 2:
			case 80:
				strncpy(powerlevel,"80",sizeof(powerlevel)-1);
				break;
			case 1:
			case 100:
				strncpy(powerlevel,"100",sizeof(powerlevel)-1);
				break;
			default:
				break;
		}
		strncpy(TxPower, powerlevel, sizeof(TxPower) - 1);
		cJSON_AddNumberToObject(WifiConfig5g, "TransmitPower", atoi(TxPower));

		bzero(buffer, sizeof(buffer));
		if ( 0 == tcapi_get(nodeName, "HT_MCS" , buffer)&& 0 != buffer[0])
		{
			if( !strcmp(buffer,"33"))
			{
				cJSON_AddStringToObject(WifiConfig5g, "X_Wlan11NHtMcs", "Auto");
			}
			else
			{
				cJSON_AddStringToObject(WifiConfig5g, "X_Wlan11NHtMcs", buffer);	
			}
		}

		bzero(buffer, sizeof(buffer));
		if ( 0 == tcapi_get(nodeName, "EncrypType" , buffer)&& 0 != buffer[0])
			cJSON_AddStringToObject(WifiConfig5g, "MixedEncryptionModes", buffer);	

		bzero(buffer, sizeof(buffer));
		if ( 0 == tcapi_get("WLan11ac_Common", "WirelessMode" , buffer)&& 0 != buffer[0])
		{
			if( !strcmp(buffer,"2"))
			{
				cJSON_AddStringToObject(WifiConfig5g, "WlanStandard", "a");
			}
			else if(!strcmp(buffer,"11"))
			{
				cJSON_AddStringToObject(WifiConfig5g, "WlanStandard", "a/n/ac");
				bzero(buffer, sizeof(buffer));
				bzero(buffer1, sizeof(buffer1));
				bzero(buffer2, sizeof(buffer2));
				tcapi_get("WLan11ac_Common", "HT_BW" , buffer);
				tcapi_get("WLan11ac_Common", "VHT_BW" , buffer1);
				tcapi_get("WLan11ac_Common", "HT_EXTCHA" , buffer2);
				if(!strcmp(buffer,"0") && !strcmp(buffer1,"0") &&!strcmp(buffer2,"1"))
				{
					cJSON_AddStringToObject(WifiConfig5g, "X_Wlan11NBWControl", "20");					
				}
				else if(!strcmp(buffer,"1") && !strcmp(buffer1,"0") &&!strcmp(buffer2,"1"))
				{
					cJSON_AddStringToObject(WifiConfig5g, "X_Wlan11NBWControl", "20_40"); 					
				}
				else if(!strcmp(buffer,"1") && !strcmp(buffer1,"1") &&!strcmp(buffer2,"0"))
				{
					cJSON_AddStringToObject(WifiConfig5g, "X_Wlan11NBWControl", "80");					
				
				}
			}
		}	

		bzero(buffer, sizeof(buffer));
		if ( 0 == tcapi_get("WLan11ac_Common", "APOn" , buffer)&& 0 != buffer[0])
			cJSON_AddBoolToObject(WifiConfig5g, "WifiEnable", atoi(buffer));

		cJSON_AddStringToObject(WifiConfig5g, "FrequencyBand", "5GHz");

		cJSON_AddNumberToObject(WifiConfig5g, "WifiSsidIndex", atoi(WifiSsidIndex));	
		
		bzero(buffer, sizeof(buffer));
		if ( 0 == tcapi_get(nodeName, "EnableSSID" , buffer)&& 0 != buffer[0])
			cJSON_AddBoolToObject(WifiConfig5g, "WifiSsidEnable", atoi(buffer));
		
		bzero(buffer, sizeof(buffer));
		if ( 0 == tcapi_get(nodeName, "HideSSID" , buffer)&& 0 != buffer[0])
			cJSON_AddBoolToObject(WifiConfig5g, "WifiHideBroadcast", atoi(buffer));

		bzero(buffer, sizeof(buffer));
		if ( 0 == tcapi_get(nodeName, "SSID" , buffer)&& 0 != buffer[0])
			cJSON_AddStringToObject(WifiConfig5g, "WifiSsid", buffer);

		bzero(buffer, sizeof(buffer));
		if ( 0 == tcapi_get("WLan11ac_Common", "VHT_SGI" , buffer)&& 0 != buffer[0])
		{
			if( !strcmp(buffer,"0"))
			{
				cJSON_AddStringToObject(WifiConfig5g, "X_Wlan11NGIControl", "long");			
			}
			else if(!strcmp(buffer,"1"))
			{
				cJSON_AddStringToObject(WifiConfig5g, "X_Wlan11NGIControl", "short");	
			}
		}
		
		// zzx ???
		cJSON_AddBoolToObject(WifiConfig5g, "X_WlanIsolateControl", 1);

		bzero(buffer, sizeof(buffer));
		if ( 0 == tcapi_get("Info_WLan11ac", "CurrentChannel", buffer)&& 0 != buffer[0])
			cJSON_AddNumberToObject(WifiConfig5g, "Channel", atoi(buffer));

		bzero(buffer, sizeof(buffer));
		if ( 0 == tcapi_get("WLan11ac_Common", "MaxStaNum", buffer)&& 0 != buffer[0])
			cJSON_AddNumberToObject(WifiConfig5g, "X_AssociateDeviceNum", atoi(buffer));
	}
	tx_body = cJSON_PrintUnformatted(jsonSend);
	cJSON_Delete(jsonSend);
	if(VCONS_COAP == construct->type)
	{
		construct->set_header(resp, &coaphead, data_in_memory.accessToken);
		coap_set_headrespkey(construct, req, resp );
	}
	else if(VCONS_HTTP == construct->type)
	{
		construct->set_header(resp, "Content-Type", MIME_TYPE_JSON);
		construct->set_header(resp, "Content-Length", intIntoString(strlen(tx_body), slen, sizeof(slen)));
	}	
	if(tx_body)
	{
		DBGPRINT(DEBUG_INFO, "tx_body:%s !!!\n",tx_body);
		construct->set_body(resp, tx_body, strlen(tx_body));
		free(tx_body);
	}
	return 0;
}

int  checkKeyValue(char* securityMode, char* keyValue)
{
	int keylen = 0, weptype = 0;
	
	if(securityMode == NULL ||keyValue == NULL )
	{
		return -1;
	}

	if(!strcasecmp(securityMode, "None") || !strcasecmp(securityMode, "Open"))
	{
		return 0;
	}

	if( 0 == keyValue[0] )
		return -1;
/*
	if (-1 == checkInvalidcharacter(keyValue))
	{
		return -1;	
	}
*/	
	keylen = strlen(keyValue);
	if( !strcmp(securityMode, "WEP-64") )
	{
		if( 5 == keylen || 10 == keylen )
			weptype = 1;
		else
			return -1;
	}
	else if( !strcmp(securityMode, "WEP-128") )
	{
		if( 13 == keylen || 26 == keylen )
			weptype = 2;
		else
			return -1;
	}
	else if( !strcmp(securityMode, "WEP") )
	{
		if( 5 == keylen || 10 == keylen )
			weptype = 1;
		else if( 13 == keylen || 26 == keylen )
			weptype = 2;
		else
			return -1;
	}

	if( weptype )
	{
		if( 10 == keylen || 26 == keylen)
		{
			if( -1 == checkHexcharacter(keyValue))
			{
				return -1;
			}
		}
		return weptype;
	}
	else
	{ 
		if(8 > keylen || 64 < keylen)	
		{
			return -1;
		}

		if(64 == keylen)
		{
			if( -1 == checkHexcharacter(keyValue))
			{
				return -1;
			}
		}
	}

	return 0;
}

int WlanGuideBasic_set_authodandpwd( char *SecurityMode , char *Pwd ,char *nodeName)
{
	int ret = 0,chgflag =0;
	char attrName[64] = {0};
	//char nodeName[64] = {0};
	char WifiSsidIndex[32] = {0};
	char WPSConfMode[8] = {0};
	char DefaultKeyID[8] = {0};
	char tmpbuf[128] = {0};
	ret = checkKeyValue(SecurityMode, Pwd);
	if (-1 == ret)
	{
		DBGPRINT(DEBUG_INFO,"[%s:%d]:Invalid Argument ,SecurityMode=[%s],Pwd=[%s]===========>\n",__FUNCTION__,__LINE__,SecurityMode, Pwd);
		return -1;// Invalid Argument 
	}

	DBGPRINT(DEBUG_INFO,"ret ：%d ,SecurityMode=[%s],Pwd=[%s],nodeName:%s ===========>\n",ret,SecurityMode, Pwd,nodeName);
	if(!strcasecmp(SecurityMode, "None") || !strcasecmp(SecurityMode, "Open"))
	{
		memset(tmpbuf, 0, sizeof(tmpbuf));
		tcapi_get(nodeName, "AuthMode", tmpbuf);
		if( strcmp(tmpbuf, "OPEN") )
		{
			tcapi_set(nodeName, "AuthMode" , "OPEN");
			chgflag = 1;
		}			
	}
	else if(1 == ret)/* WEB-64 */
	{
		memset(WPSConfMode, 0, sizeof(WPSConfMode));
		if(0 == tcapi_get(nodeName, "WPSConfMode", WPSConfMode) && WPSConfMode[0] != '\0')
		{
			if(atoi(WPSConfMode))
			{
				tcapi_set(nodeName, "WPSConfMode" , "0");
				chgflag = 1;
			}
		}

		memset(attrName, 0, sizeof(attrName));
		memset(DefaultKeyID, 0, sizeof(DefaultKeyID));
		if(0 == tcapi_get(nodeName, "DefaultKeyID", DefaultKeyID) && DefaultKeyID[0] != '\0')
		{
			snprintf(attrName, sizeof(attrName), "Key%sStr", DefaultKeyID);
		}
		else
		{
			tcapi_set(nodeName, "DefaultKeyID" , "1");
			snprintf(attrName, sizeof(attrName), "Key1Str");
		}
		memset(tmpbuf, 0, sizeof(tmpbuf));
		tcapi_get(nodeName, attrName, tmpbuf);
		if( strcmp(tmpbuf, Pwd) )
		{
			tcapi_set(nodeName, attrName , Pwd);
			chgflag = 1;
		}

		memset(tmpbuf, 0, sizeof(tmpbuf));
		tcapi_get(nodeName, "AuthMode", tmpbuf);
		if( strcmp(tmpbuf, "WEP-64Bits") )
		{
			tcapi_set(nodeName, "AuthMode" , "WEP-64Bits");
			chgflag = 1;
		}
		
	}
	else if(2 == ret)/* WEB-128 */
	{
		memset(WPSConfMode, 0, sizeof(WPSConfMode));
		if(0 == tcapi_get(nodeName, "WPSConfMode", WPSConfMode) && WPSConfMode[0] != '\0')
		{
			if(atoi(WPSConfMode))
			{
				tcapi_set(nodeName, "WPSConfMode" , "0");
				chgflag = 1;
			}
		}

		memset(attrName, 0, sizeof(attrName));
		memset(DefaultKeyID, 0, sizeof(DefaultKeyID));
		if(0 == tcapi_get(nodeName, "DefaultKeyID", DefaultKeyID) && DefaultKeyID[0] != '\0')
		{
			snprintf(attrName, sizeof(attrName), "Key%sStr", DefaultKeyID);
		}
		else
		{
			tcapi_set(nodeName, "DefaultKeyID" , "1");
			snprintf(attrName, sizeof(attrName), "Key1Str");
		}
		memset(tmpbuf, 0, sizeof(tmpbuf));
		tcapi_get(nodeName, attrName, tmpbuf);
		if( strcmp(tmpbuf,Pwd) )
		{
			tcapi_set(nodeName, attrName , Pwd);
			chgflag = 1;
		}

		memset(tmpbuf, 0, sizeof(tmpbuf));
		tcapi_get(nodeName, "AuthMode", tmpbuf);
		if( strcmp(tmpbuf, "WEP-128Bits") )
		{
			tcapi_set(nodeName, "AuthMode" , "WEP-128Bits");
			chgflag = 1;
		}
	}
	else if( !strcmp(SecurityMode, "WPA-Personal") || !strcmp(SecurityMode, "WPAPSK") )
	{
		memset(tmpbuf, 0, sizeof(tmpbuf));
		tcapi_get(nodeName, "WPAPSK", tmpbuf);
		if( strcmp(tmpbuf, Pwd) )
		{
			tcapi_set(nodeName, "WPAPSK" , Pwd);
			chgflag = 1;
		}

		memset(tmpbuf, 0, sizeof(tmpbuf));
		tcapi_get(nodeName, "AuthMode", tmpbuf);
		if( strcmp(tmpbuf, "WPAPSK") )
		{
			tcapi_set(nodeName, "AuthMode" , "WPAPSK");	
			chgflag = 1;
		}	
	}
	else if( !strcmp(SecurityMode, "WPA2-Personal") || !strcmp(SecurityMode, "WPA2PSK") || !strcmp(SecurityMode, "WPAPSK2"))
	{
		memset(tmpbuf, 0, sizeof(tmpbuf));
		tcapi_get(nodeName, "WPAPSK", tmpbuf);
		if( strcmp(tmpbuf, Pwd) )
		{
			tcapi_set(nodeName, "WPAPSK" , Pwd);
			chgflag = 1;
		}
		DBGPRINT(DEBUG_INFO,"tmpbuf1:%s ,chgflag:%d ===========>\n",tmpbuf,chgflag);

		memset(tmpbuf, 0, sizeof(tmpbuf));
		tcapi_get(nodeName, "AuthMode", tmpbuf);
		if( strcmp(tmpbuf, "WPA2PSK") )
		{
			tcapi_set(nodeName, "AuthMode" , "WPA2PSK");
			chgflag = 1;
		}	
		DBGPRINT(DEBUG_INFO,"tmpbuf2:%s ,chgflag:%d ===========>\n",tmpbuf,chgflag);
	}
	else if( !strcmp(SecurityMode, "MIXED-WPAPSK2") || !strcmp(SecurityMode, "WPAPSKWPA2PSK") || !strcmp(SecurityMode, "WPAPSKWPAPSK2"))
	{
		memset(tmpbuf, 0, sizeof(tmpbuf));
		tcapi_get(nodeName, "WPAPSK", tmpbuf);
		if( strcmp(tmpbuf, Pwd) )
		{
			tcapi_set(nodeName, "WPAPSK" , Pwd);
			chgflag = 1;
		}

		memset(tmpbuf, 0, sizeof(tmpbuf));
		tcapi_get(nodeName, "AuthMode", tmpbuf);
		if( strcmp(tmpbuf, "WPAPSKWPA2PSK") )
		{
			tcapi_set(nodeName, "AuthMode" , "WPAPSKWPA2PSK");
			chgflag = 1;
		}
	}

	DBGPRINT(DEBUG_INFO,"chgflag:%d  ===========>\n",chgflag);
	return chgflag;
}

int handle_WlanGuideBasic(virtual_construct_t*construct,void*req,void*resp)
{
	char buffer[64] = {0};
	char nodeName[64] = {0};
	char WifiSsidIndex[32] = {0};
	char WPSConfMode[8] = {0};
	char DefaultKeyID[8] = {0};
	char slen[32] = {0};
	char *body = NULL, *tx_body = NULL;
	int body_len = 0,DbhoEnable = 0 ,advertisement = 0,errcode = 0 ,wpaencmode_flag = 0,chgflag = 0,ret =0,chgflag1 = 0,ret1 =0;
	char *ssid = NULL, *beacontype = NULL, *wpaencmode = NULL,*wpakey = NULL;
	char *guest2g_ID = NULL, *guest2g_WifiSsid = NULL, *guest5g_ID = NULL,*guest5g_WifiSsid = NULL;
	cJSON *root = NULL, *date = NULL, *jsonSend = NULL,*config2g = NULL, *config5g = NULL, *guest2g = NULL, *guest5g = NULL;
	unsigned short coaphead = COAP_OPT_ACCESS_TOKEN_ID;
	bool setGuestSsid = false;
	bool ssidenable = false;
	char SecurityMode[32] = {0};
	
	DBGPRINT(DEBUG_INFO,"\n\n zzx111  printf  req =================>>>>> ");
    coap_show_pdu(LOG_INFO, (coap_pdu_t *)req);
	printf("\n ");

	
	if(VCONS_COAP == construct->type)
	{
		construct->set_code(resp, 201);
	}
	else if(VCONS_HTTP == construct->type)
	{
		construct->set_code(resp, 200);	
	}

	construct->get_body(req, &body, &body_len);
	if(body)
	{
		if(root = cJSON_Parse(body))
		{
			date = cJSON_GetObjectItem(root, "data");			
			cJSON_GetIntByKey(date, "DbhoEnable", DbhoEnable);
			config2g = cJSON_GetObjectItem(date, "config2g");			
			cJSON_GetIntByKey(config2g, "setGuestSsid", setGuestSsid);
			if( setGuestSsid == 1)
			{
				DBGPRINT(DEBUG_INFO,"[%s:%d]:setGuestSsid ture  !!!===========>\n",__FUNCTION__,__LINE__);
				guest2g = cJSON_GetObjectItem(date, "guest2g");			
				guest5g = cJSON_GetObjectItem(date, "guest5g");			
				cJSON_GetStringByKey(guest2g, "ID", guest2g_ID);
				cJSON_GetStringByKey(guest2g, "WifiSsid", guest2g_WifiSsid);
				cJSON_GetStringByKey(guest5g, "ID", guest5g_ID);
				cJSON_GetStringByKey(guest5g, "WifiSsid", guest5g_WifiSsid);
			}

			if(config2g)
			{
				cJSON_GetStringByKey(config2g, "ssid", ssid);
				cJSON_GetIntByKey(config2g, "ssidenable", ssidenable);
				cJSON_GetStringByKey(config2g, "beacontype", beacontype);
				cJSON_GetStringByKey(config2g, "wpaencmode", wpaencmode);
				cJSON_GetStringByKey(config2g, "wpakey", wpakey);
				cJSON_GetIntByKey(config2g, "advertisement", advertisement);
				DBGPRINT(DEBUG_INFO,"2g ====>>>> ssid:%s,ssidenable:%d,beacontype:%s,wpaencmode:%s,wpakey:%s,advertisement:%d \n",ssid,ssidenable,beacontype,wpaencmode,wpakey,advertisement);
		
				bzero(WifiSsidIndex, sizeof(WifiSsidIndex));
				if ( 0 == tcapi_get("WebCurSet_Entry", "wlan_id", WifiSsidIndex)&& 0 != WifiSsidIndex[0])
				{
					memset(nodeName, 0, sizeof(nodeName));
					snprintf(nodeName, sizeof(nodeName), "WLan_Entry%d", atoi(WifiSsidIndex));
				}

				memset(buffer, 0, sizeof(buffer));
				tcapi_get(nodeName, "EnableSSID", buffer);
				DBGPRINT(DEBUG_INFO,"[%s:%d]:ssidenable :%d ,buffer:%s,chgflag:%d!!!===========>\n",__FUNCTION__,__LINE__,ssidenable,buffer,chgflag);
				if( atoi(buffer) != ssidenable  )
				{
					tcapi_set(nodeName, "EnableSSID" , itoa(ssidenable));
					chgflag = 1;
				}

				if (ssid)
				{
					memset(buffer, 0, sizeof(buffer));
					tcapi_get(nodeName, "SSID", buffer);
					if( strcmp(buffer, ssid) )
					{
						tcapi_set(nodeName, "SSID" , ssid);
						chgflag = 1;
					}
				}
				else
				{
					DBGPRINT(DEBUG_INFO,"[%s:%d]:Do not have ssid attribute!!!===========>\n",__FUNCTION__,__LINE__);
				}

				if( advertisement==1 )
					advertisement = 0;
				else if(advertisement==0)
					advertisement = 1;
				memset(buffer, 0, sizeof(buffer));
				tcapi_get(nodeName, "HideSSID", buffer);
				DBGPRINT(DEBUG_INFO,"[%s:%d]:advertisement :%d ,buffer:%s,chgflag:%d!!!===========>\n",__FUNCTION__,__LINE__,advertisement,buffer,chgflag);
				if( atoi(buffer) != advertisement )
				{
					tcapi_set(nodeName, "HideSSID" , itoa(advertisement));
					chgflag = 1;
				}

				DBGPRINT(DEBUG_INFO,"[%s:%d]:beacontype :%s,chgflag:%d !!!===========>\n",__FUNCTION__,__LINE__,beacontype,chgflag);
				if( !strcmp(beacontype,"WPAand11i"))
				{
					snprintf(SecurityMode, sizeof(SecurityMode), "WPAPSKWPA2PSK");
					wpaencmode_flag = 1;
				}
				else if(!strcmp(beacontype,"11i"))
				{
					snprintf(SecurityMode, sizeof(SecurityMode), "WPA2PSK");
					wpaencmode_flag = 1;	
				}
				else if(!strcmp(beacontype,"WPA"))
				{
					snprintf(SecurityMode, sizeof(SecurityMode), "WPAPSK");
					wpaencmode_flag = 1;
				}	
				else if(!strcmp(beacontype,"None"))
				{
					snprintf(SecurityMode, sizeof(SecurityMode), "OPEN");
				}
				else if( strstr(beacontype, "WEP") )
				{
					snprintf(SecurityMode, sizeof(SecurityMode), "WEP");
				}
				else
				{
					DBGPRINT(DEBUG_INFO,"beacontype  error !!! ===========>\n");						
					errcode = -1;
					goto send;
				}
				
				if( wpaencmode_flag == 1 && wpaencmode )
				{
					memset(buffer, 0, sizeof(buffer));
					if ( 0 == tcapi_get(nodeName, "EncrypType", buffer)&& 0 != buffer[0])
					{
						DBGPRINT(DEBUG_INFO,"[%s:%d]:wpaencmode_flag :%d ,buffer:%s,chgflag:%d !!!===========>\n",__FUNCTION__,__LINE__,wpaencmode_flag,buffer,chgflag);
						if( strcmp(buffer, wpaencmode)	)
						{
							tcapi_set(nodeName, "EncrypType" , wpaencmode );
							chgflag = 1;
						}
					}
				}
				
				//zzx???解密wifi密码
				//pwd=fuc();
				DBGPRINT(DEBUG_INFO,"SecurityMode : %s ,wpakey: %s  !!!===========>\n",SecurityMode,wpakey);
				if( SecurityMode && wpakey )
					ret = WlanGuideBasic_set_authodandpwd(SecurityMode,wpakey,nodeName);

				DBGPRINT(DEBUG_INFO,"[%s:%d]: 1111 ret:%d ,chgflag:%d,nodeName:%s !!!===========>\n",__FUNCTION__,__LINE__,ret,chgflag,nodeName); 
				if(chgflag == 1 || ret == 1 )
				{
					tcapi_set(nodeName, "wlan_changed", "1");
					DBGPRINT(DEBUG_INFO, "WLan commit !!!\n");
					tcapi_commit("WLan");
				}
			}

			memset(buffer, 0, sizeof(buffer));
			if ( 0 == tcapi_get("WLan11ac_common", "DbhoEnable", buffer)&& 0 != buffer[0])
			{
				DBGPRINT(DEBUG_INFO,"1.1 have and differ,set DbhoEnable .buffer:%s,DbhoEnable:%d\n",buffer,DbhoEnable);
				if( atoi(buffer) != DbhoEnable  )
				{
					tcapi_set("WLan11ac_common", "DbhoEnable" , itoa(DbhoEnable));
					chgflag1 = 1;
				}
			}
			else
			{
				DBGPRINT(DEBUG_INFO,"1.1 not have ,set DbhoEnable \n");
				tcapi_set("WLan11ac_common", "DbhoEnable" ,itoa(DbhoEnable));
				chgflag1 = 1;
			}

			if( DbhoEnable == 1 )
			{	
				DBGPRINT(DEBUG_INFO,"DbhoEnable = 1 \n");
			}
			else
			{
				config5g = cJSON_GetObjectItem(date, "config5g");
				if(config5g)
				{	
					cJSON_GetStringByKey(config5g, "ssid", ssid);
					cJSON_GetIntByKey(config5g, "ssidenable", ssidenable);
					cJSON_GetStringByKey(config5g, "beacontype", beacontype);
					cJSON_GetStringByKey(config5g, "wpaencmode", wpaencmode);
					cJSON_GetStringByKey(config5g, "wpakey", wpakey);
					cJSON_GetIntByKey(config5g, "advertisement", advertisement);
					
					if( advertisement == 1 )
						advertisement = 0;
					else if( advertisement == 0)
						advertisement = 1;
				}	
				DBGPRINT(DEBUG_INFO,"5g ====>>>> DbhoEnable = 0,ssid:%s,ssidenable:%d,beacontype:%s,wpaencmode:%s,wpakey:%s,advertisement:%d \n",ssid,ssidenable,beacontype,wpaencmode,wpakey,advertisement);
			}
			
			if(1)//and set for 5g
			{
				memset(WifiSsidIndex, 0, sizeof(WifiSsidIndex));
				if ( 0 == tcapi_get("WebCurSet_Entry", "wlan_ac_id", WifiSsidIndex)&& 0 != WifiSsidIndex[0])
				{
					memset(nodeName, 0, sizeof(nodeName));
					snprintf(nodeName, sizeof(nodeName), "WLan11ac_Entry%d", atoi(WifiSsidIndex));
				}
				
				memset(buffer, 0, sizeof(buffer));
				tcapi_get(nodeName, "EnableSSID", buffer);
				DBGPRINT(DEBUG_INFO,"[%s:%d]:ssidenable :%d ,buffer:%s,chgflag:%d!!!===========>\n",__FUNCTION__,__LINE__,ssidenable,buffer,chgflag);
				if( atoi(buffer) != ssidenable	)
				{
					tcapi_set(nodeName, "EnableSSID" , itoa(ssidenable));
					chgflag1 = 1;
				}
				
				if (ssid)
				{
					memset(buffer, 0, sizeof(buffer));
					tcapi_get(nodeName, "SSID", buffer);
					if( strcmp(buffer, ssid) )
					{
						tcapi_set(nodeName, "SSID" , ssid);
						chgflag1 = 1;
					}
				}
				else
				{
					DBGPRINT(DEBUG_INFO,"[%s:%d]:Do not have ssid attribute!!!===========>\n",__FUNCTION__,__LINE__);
				}
				
				memset(buffer, 0, sizeof(buffer));
				tcapi_get(nodeName, "HideSSID", buffer);
				DBGPRINT(DEBUG_INFO,"[%s:%d]:advertisement :%d ,buffer:%s,chgflag:%d!!!===========>\n",__FUNCTION__,__LINE__,advertisement,buffer,chgflag);
				if( atoi(buffer) != advertisement )
				{
					tcapi_set(nodeName, "HideSSID" , itoa(advertisement));
					chgflag = 1;
				}
				
				DBGPRINT(DEBUG_INFO,"[%s:%d]:beacontype :%s,chgflag:%d !!!===========>\n",__FUNCTION__,__LINE__,beacontype,chgflag);
				if( !strcmp(beacontype,"WPAand11i"))
				{
					snprintf(SecurityMode, sizeof(SecurityMode), "WPAPSKWPA2PSK");
					wpaencmode_flag = 1;
				}
				else if(!strcmp(beacontype,"11i"))
				{
					snprintf(SecurityMode, sizeof(SecurityMode), "WPA2PSK");
					wpaencmode_flag = 1;
				}
				else if(!strcmp(beacontype,"WPA"))
				{
					snprintf(SecurityMode, sizeof(SecurityMode), "WPAPSK");
					wpaencmode_flag = 1;
				}	
				else if(!strcmp(beacontype,"None"))
				{
					snprintf(SecurityMode, sizeof(SecurityMode), "OPEN");
				}
				else if (strstr(beacontype, "WEP"))
				{
					snprintf(SecurityMode, sizeof(SecurityMode), "WEP");
				}
				else
				{
					DBGPRINT(DEBUG_INFO,"[%s:%d]:beacontype  error !!!===========>\n",__FUNCTION__,__LINE__);
					errcode = -1;
					goto send;
				}
				
				if( wpaencmode_flag == 1 && wpaencmode )
				{
					DBGPRINT(DEBUG_INFO,"[%s:%d]:wpaencmode_flag :%d ,buffer:%s,chgflag:%d !!!===========>\n",__FUNCTION__,__LINE__,wpaencmode_flag,buffer,chgflag);
					memset(buffer, 0, sizeof(buffer));
					if ( 0 == tcapi_get(nodeName, "EncrypType", buffer)&& 0 != buffer[0])
					{
						if( strcmp(buffer, wpaencmode)	)
						{
							tcapi_set(nodeName, "EncrypType" , wpaencmode );
							chgflag1 = 1;
						}
					}
				}
				//zzx???解密wifi密码
				//pwd=fuc();
				ret1 = WlanGuideBasic_set_authodandpwd(SecurityMode,wpakey,nodeName);
				DBGPRINT(DEBUG_INFO,"[%s:%d]: 2222 ret1:%d ,chgflag1:%d !!!===========>\n",__FUNCTION__,__LINE__,ret1,chgflag1); 
				if(chgflag1 == 1 || ret1 == 1)
				{
					DBGPRINT(DEBUG_INFO, "WLan11ac commit !!!\n");
					tcapi_set(nodeName, "wlan_changed", "1");
					tcapi_commit("WLan11ac");
				}
			}	
			if(chgflag == 1 || ret == 1 || chgflag1 == 1 || ret1 == 1)
			{
				DBGPRINT(DEBUG_INFO, "tcapi_save !!!\n");
				tcapi_save();		
			}
		}
		
		cJSON_Delete(root);
	}

send:
	jsonSend = cJSON_CreateObject();
	cJSON_AddNumberToObject(jsonSend, "errcode", errcode);
	tx_body = cJSON_PrintUnformatted(jsonSend);
	cJSON_Delete(jsonSend);
	if(VCONS_COAP == construct->type)
	{
		construct->set_header(resp, &coaphead, data_in_memory.accessToken);
		coap_set_headrespkey(construct, req, resp );
	}
	else if(VCONS_HTTP == construct->type)
	{
		construct->set_header(resp, "Content-Type", MIME_TYPE_JSON);
		construct->set_header(resp, "Content-Length", intIntoString(strlen(tx_body), slen, sizeof(slen)));
	}
	if(tx_body)
	{
		DBGPRINT(DEBUG_INFO, "tx_body:%s !!!\n",tx_body);
		construct->set_body(resp, tx_body, strlen(tx_body));
		free(tx_body);
	}
	WF_FREE(guest2g_ID);
	WF_FREE(guest2g_WifiSsid);
	WF_FREE(guest5g_ID);
	WF_FREE(guest5g_WifiSsid);
	WF_FREE(ssid);
	WF_FREE(beacontype);
	WF_FREE(wpaencmode);
	WF_FREE(wpakey);
	return 0;
}

int handle_WlanBasic(virtual_construct_t*construct,void*req,void*resp)
{
	char buffer[64] = {0};
	char nodeName[64] = {0};
	char slen[32] = {0};
	char *body = NULL, *tx_body = NULL, *action = NULL;
	int body_len = 0,config2g_ID = 0,config2g_enable = 0,config5g_ID = 0,config5g_enable = 0, errcode = 0,chgflag=0;
	int DbhoEnable = 0 ,ssidenable = 0;
	cJSON *root = NULL, *date = NULL, *jsonSend = NULL, *config2g = NULL, *config5g = NULL;
	char *ssid = NULL, *beacontype = NULL, *wpaencmode = NULL,*wpakey = NULL,*advertisement = NULL,*upassword = NULL,*Pwd = NULL,*SecurityMode = NULL;
	unsigned short coaphead = COAP_OPT_ACCESS_TOKEN_ID;

	printf("\n\n zzx111  printf  req =================>>>>> ");
    coap_show_pdu(LOG_INFO, (coap_pdu_t *)req);
	printf("\n ");
	
	if(VCONS_COAP == construct->type)
	{
		construct->set_code(resp, 201);
	} 
	else if(VCONS_HTTP == construct->type)
	{
		construct->set_code(resp, 200);	
	}

	construct->get_body(req, &body, &body_len);
	if(body)
	{
		if(root = cJSON_Parse(body))
		{
			cJSON_GetStringByKey(root, "data", date);
			cJSON_GetStringByKey(root, "action", action);
			cJSON_GetStringByKey(date, "config2g", config2g);
			cJSON_GetStringByKey(date, "config5g", config5g);
			if( !strcmp(action, "BasicSettings"))
			{
				cJSON_GetIntByKey(config2g, "ID", config2g_ID);
				cJSON_GetIntByKey(config2g, "enable", config2g_enable);
				cJSON_GetIntByKey(config5g, "ID", config5g_ID);
				cJSON_GetIntByKey(config5g, "enable", config5g_enable);
				
				printf("[%s:%d]:config2g_ID :%d config2g_enable:%d!!!===========>\n",__FUNCTION__,__LINE__,config2g_ID,config2g_enable);
				if( config2g_ID == 1 )
				{
					memset(nodeName, 0, sizeof(nodeName));
					snprintf(nodeName, sizeof(nodeName), "WLan_Common");
					memset(buffer, 0, sizeof(buffer));
					tcapi_get(nodeName, "APOn", buffer);
					if( atoi(buffer) != config2g_enable  )
					{
						tcapi_set(nodeName, "APOn" , itoa(config2g_enable));
						chgflag = 1;
					}
				}

				printf("[%s:%d]:config5g_ID :%d config5g_enable:%d!!!===========>\n",__FUNCTION__,__LINE__,config5g_ID,config5g_enable);
				if( config5g_ID == 2 )
				{
					memset(nodeName, 0, sizeof(nodeName));
					snprintf(nodeName, sizeof(nodeName), "WLan11ac_Common");
					memset(buffer, 0, sizeof(buffer));
					tcapi_get(nodeName, "APOn", buffer);
					if( atoi(buffer) != config5g_enable  )
					{
						tcapi_set(nodeName, "APOn" , itoa(config5g_enable));
						chgflag = 1;
					}
				}
			}
			else if( !strcmp(action, "SsidSettings"))
			{
				cJSON_GetStringByKey(date, "DbhoEnable", DbhoEnable);
				if( DbhoEnable == 0 )//only for 2.4g
				{
					cJSON_GetStringByKey(config2g, "ssid", ssid);
					cJSON_GetIntByKey(config2g, "ssidenable", ssidenable);
					cJSON_GetStringByKey(config2g, "beacontype", beacontype);
					if( !strcmp(beacontype, "WPA") || !strcmp(beacontype, "11i") || !strcmp(beacontype, "WPAand11i"))
					{		
						cJSON_GetStringByKey(config2g, "wpaencmode", wpaencmode);
						cJSON_GetStringByKey(config2g, "wpakey", wpakey);
					
					}
					else if( !strcmp(beacontype, "None") || !strcmp(beacontype, "Basic"))
					{
											
					}
					else if( !strcmp(beacontype, "8021X"))
					{
					
					}
					cJSON_GetStringByKey(config2g, "wpaencmode", wpaencmode);
					cJSON_GetStringByKey(config2g, "wpakey", wpakey);
					cJSON_GetIntByKey(config2g, "advertisement", advertisement);
					
				}
				else if(DbhoEnable == 1)//for 2.4g and 5g
				{
					
				}
			}
			else if( !strcmp(action, "SendSettings"))
			{
				
			}
			else
			{
				errcode = -1;			
			}

		}
		cJSON_Delete(root);
	}

	jsonSend = cJSON_CreateObject();
	cJSON_AddNumberToObject(jsonSend, "errcode", errcode);
	tx_body = cJSON_PrintUnformatted(jsonSend);
	cJSON_Delete(jsonSend);
	if(VCONS_COAP == construct->type)
	{
		construct->set_header(resp, &coaphead, data_in_memory.accessToken);
		coap_set_headrespkey(construct, req, resp );
	}
	else if(VCONS_HTTP == construct->type)
	{
		construct->set_header(resp, "Content-Type", MIME_TYPE_JSON);
		construct->set_header(resp, "Content-Length", intIntoString(strlen(tx_body), slen, sizeof(slen)));
	}
	if(tx_body)
	{
		DBGPRINT(DEBUG_INFO, "tx_body:%s !!!\n",__FUNCTION__,tx_body);
		construct->set_body(resp, tx_body, strlen(tx_body));
		free(tx_body);
	}
	WF_FREE(config2g);
	WF_FREE(config5g);
	WF_FREE(ssid);
	WF_FREE(beacontype);
	WF_FREE(wpaencmode);
	WF_FREE(wpakey);
	WF_FREE(upassword);
	WF_FREE(Pwd);
	WF_FREE(SecurityMode);
	return 0;
}

int coap_set_headrespkey(virtual_construct_t*construct,void*req,void*resp)
{
	char *tmp = NULL;
	unsigned short reqidkey = COAP_OPT_REQ_ID;
	unsigned short devidkey = COAP_OPT_DEV_ID;
	unsigned short useridkey = COAP_OPT_USER_ID;
	char reqidkey_value[256] = {0};
	char devidkey_value[256] = {0};
	char useridkey_value[256] = {0};
	int ret = 0 ;		
		
	//打印收到的请求报文
	printf("\n\n zzx =================>>>>> ");
    coap_show_pdu(LOG_INFO, (coap_pdu_t *)req);
	printf("\n ");

	ret = coap_get_header(req,&reqidkey,&tmp);
	printf("\n 1=================>>>>> ret：%d  tmp:%s\n",ret,tmp);
	strncpy(reqidkey_value,tmp,ret);
	printf(" 11=================>>>>> ret：%d  devidkey_value:%s\n",ret,reqidkey_value);

	ret = coap_get_header(req,&devidkey,&tmp);
	printf("\n 2=================>>>>> ret：%d  tmp:%s\n",ret,tmp);
	strncpy(devidkey_value,tmp,ret);
	printf(" 22=================>>>>> ret：%d  devidkey_value:%s\n",ret,devidkey_value);
	
	ret = coap_get_header(req,&useridkey,&tmp);	
	//useridkey_value[ret]='\0';
	printf("\n 3 =================>>>>> ret：%d  tmp:%s\n",ret,tmp);
	strncpy(useridkey_value,tmp,ret);
	printf(" 33=================>>>>> ret：%d  devidkey_value:%s\n",ret,useridkey_value);
	
    /*req 是结构体 打印为null
	if(req)printf("\n\n =================>>>>>  req  NULL");
	*/
	
	if(reqidkey && devidkey_value && useridkey_value )
	{
		construct->set_header(resp, &reqidkey, reqidkey_value);
		construct->set_header(resp, &devidkey, devidkey_value);
		construct->set_header(resp, &useridkey, useridkey_value);
	}
	return 0;
}

int get_wlan_filterenhance(virtual_construct_t*construct,void*req,void*resp)
{
	char buffer[125] = {0};
	char time[125] = {0};
	char weekbuf[32] = {0};
	char nodeName[64] = {0};
	char slen[32] = {0};
	cJSON *jsonSend = NULL,*wlan2gfilter = NULL,*wlan5gfilter = NULL,*BMACAddresses2g = NULL,*WMACAddresses2g = NULL,*BMACAddresses5g = NULL,*WMACAddresses5g = NULL,*wlan2g_macdate = NULL,*wlan5g_macdate = NULL;
	char *tx_body = NULL;
	int i = 0, week = 0 ,timeOffset = 0, timeOffset2 = 0, minute = 0, hour = 0;
	unsigned short coaphead = COAP_OPT_ACCESS_TOKEN_ID;
		
	if(VCONS_COAP == construct->type)
	{
		construct->set_code(resp, 201);
	}
	else if(VCONS_HTTP == construct->type)
	{
		construct->set_code(resp, 200);	
		construct->set_header(resp, "Content-Type", MIME_TYPE_JSON);
	}
	
	jsonSend = cJSON_CreateArray();
	//2.4g
	wlan2gfilter = cJSON_CreateObject();
	cJSON_AddItemToArray(jsonSend,wlan2gfilter);

	cJSON_AddStringToObject(wlan2gfilter, "FrequencyBand", "2.4GHz");
	cJSON_AddStringToObject(wlan2gfilter, "ID ", "IpMacFilter_entry");
	cJSON_AddBoolToObject(wlan2gfilter, "MACAddressControlEnabled", 1);
	cJSON_AddNumberToObject(wlan2gfilter, "MacFilterPolicy", 0);

	BMACAddresses2g = cJSON_CreateArray();
	cJSON_AddItemToObject(wlan2gfilter,"BMACAddresses",BMACAddresses2g);

	WMACAddresses2g = cJSON_CreateArray();
	cJSON_AddItemToObject(wlan2gfilter,"WMACAddresses",WMACAddresses2g);

	
	wlan2g_macdate = cJSON_CreateObject();
	cJSON_AddItemToArray(BMACAddresses2g,wlan2g_macdate);

	cJSON_AddStringToObject(wlan2g_macdate, "MACAddress", "DC:EE:06:76:BB:BF");
	cJSON_AddStringToObject(wlan2g_macdate, "HostName ", "p9");


	//5g
	wlan5gfilter = cJSON_CreateObject();
	cJSON_AddItemToArray(jsonSend,wlan5gfilter);

	cJSON_AddStringToObject(wlan5gfilter, "FrequencyBand", "5GHz");
	cJSON_AddStringToObject(wlan5gfilter, "ID ", "IpMacFilter_entry");
	cJSON_AddBoolToObject(wlan5gfilter, "MACAddressControlEnabled", 1);
	cJSON_AddNumberToObject(wlan5gfilter, "MacFilterPolicy", 0);

	BMACAddresses5g = cJSON_CreateArray();
	cJSON_AddItemToObject(wlan5gfilter,"BMACAddresses",BMACAddresses5g);

	WMACAddresses5g = cJSON_CreateArray();
	cJSON_AddItemToObject(wlan5gfilter,"WMACAddresses",WMACAddresses5g);


	wlan5g_macdate = cJSON_CreateObject();
	cJSON_AddItemToArray(BMACAddresses5g,wlan5g_macdate);

	cJSON_AddStringToObject(wlan5g_macdate, "MACAddress", "94:FE:22:E9:BC:71");
	cJSON_AddStringToObject(wlan5g_macdate, "HostName ", "Honor_8");
	
	tx_body = cJSON_PrintUnformatted(jsonSend);
	cJSON_Delete(jsonSend);
	if(VCONS_COAP == construct->type)
	{
		construct->set_header(resp, &coaphead, data_in_memory.accessToken);
		coap_set_headrespkey(construct, req, resp );
	}
	else if(VCONS_HTTP == construct->type)
	{
		construct->set_header(resp, "Content-Type", MIME_TYPE_JSON);
		construct->set_header(resp, "Content-Length", intIntoString(strlen(tx_body), slen, sizeof(slen)));
	}
	
	if(tx_body)
	{
		DBGPRINT(DEBUG_INFO, "tx_body:%s !!!\n",tx_body);
		construct->set_body(resp, tx_body, strlen(tx_body));
		free(tx_body);
	}
	return 0;
}

int handle_wlan_filterenhance(virtual_construct_t*construct,void*req,void*resp)
{
	char buffer[64] = {0};
	char nodeName[64] = {0};
	char slen[32] = {0};
	char *body = NULL, *tx_body = NULL;
	int body_len = 0, errcode = 0, chgflag = 0;
	cJSON *root = NULL, *date = NULL, *jsonSend = NULL, *config2g = NULL, *config5g = NULL , *WMacFilters2g = NULL, *BMacFilters2g = NULL , *WMacFilters5g = NULL, *BMacFilters5g = NULL;
	char *MACAddressControlEnabled = NULL, *MacFilterPolicy = NULL , *FrequencyBand = NULL, *ID = NULL;
	unsigned short coaphead = COAP_OPT_ACCESS_TOKEN_ID;
		
	if(VCONS_COAP == construct->type)
	{
		construct->set_code(resp, 201);
	}
	else if(VCONS_HTTP == construct->type)
	{
		construct->set_code(resp, 200);	
		construct->set_header(resp, "Content-Type", MIME_TYPE_JSON);
	}

	construct->get_body(req, &body, &body_len);
	if(body)
	{
		if(root = cJSON_Parse(body))
		{
			cJSON_GetStringByKey(root, "date", date);		
			cJSON_GetStringByKey(date, "config2g", config2g);
			cJSON_GetStringByKey(date, "config5g", config5g);

			cJSON_GetIntByKey(config2g, "MACAddressControlEnabled", MACAddressControlEnabled);
			cJSON_GetIntByKey(config2g, "MacFilterPolicy", MacFilterPolicy);
			cJSON_GetStringByKey(config2g, "ID", ID);
			cJSON_GetStringByKey(config2g, "FrequencyBand", FrequencyBand);
			cJSON_GetStringByKey(config2g, "WMacFilters ", WMacFilters2g );
			cJSON_GetStringByKey(config2g, "BMacFilters", BMacFilters2g );

			
			cJSON_GetIntByKey(config5g, "MACAddressControlEnabled", MACAddressControlEnabled);
			cJSON_GetIntByKey(config5g, "MacFilterPolicy", MacFilterPolicy);
			cJSON_GetStringByKey(config5g, "ID", ID);
			cJSON_GetStringByKey(config5g, "FrequencyBand", FrequencyBand);
			cJSON_GetStringByKey(config5g, "WMacFilters ", WMacFilters5g );
			cJSON_GetStringByKey(config5g, "BMacFilters", BMacFilters5g );
		}
		cJSON_Delete(root);
	}	

	jsonSend = cJSON_CreateObject();
	cJSON_AddNumberToObject(jsonSend, "errcode", errcode);
	tx_body = cJSON_PrintUnformatted(jsonSend);
	cJSON_Delete(jsonSend);
	if(VCONS_COAP == construct->type)
	{
		construct->set_header(resp, &coaphead, data_in_memory.accessToken);
		coap_set_headrespkey(construct, req, resp );
	}
	else if(VCONS_HTTP == construct->type)
	{
		construct->set_header(resp, "Content-Type", MIME_TYPE_JSON);
		construct->set_header(resp, "Content-Length", intIntoString(strlen(tx_body), slen, sizeof(slen)));
	}
	if(tx_body)
	{
		DBGPRINT(DEBUG_INFO, "tx_body:%s !!!\n",__FUNCTION__,tx_body);
		construct->set_body(resp, tx_body, strlen(tx_body));
		free(tx_body);
	}
	WF_FREE(MACAddressControlEnabled);
	WF_FREE(MacFilterPolicy);
	WF_FREE(FrequencyBand);
	WF_FREE(ID);
	return 0;
}


static int _get_weeks(char *buffer, int buflen, int week)
{
	DBGPRINT(DEBUG_INFO, "week:%d !!!\n",week);
	int i = 0;
	int count = 0;
	int len = 0;
	if(buffer)
	{
		for(i = 1; i < 8; i++)
		{
			if(week & (1 << i))
			{
				len += snprintf(buffer + len, buflen - len, "%d%s", i, count++ ? "," : "");
				DBGPRINT(DEBUG_INFO, "i:%d ,buffer:%s!!!\n",i,buffer);
			}
		}
	}
	return len;
}

int get_wlan_timeswitch(virtual_construct_t*construct,void*req,void*resp)
{
	char buffer[125] = {0};
	char time[125] = {0};
	char slen[32] = {0};
	char weekbuf[32] = {0};
	char nodeName[64] = {0};
	cJSON *jsonSend = NULL,*datelist = NULL,*wlandate = NULL;
	char *tx_body = NULL;
	int i = 0, week = 0 ,timeOffset = 0, timeOffset2 = 0, minute = 0, hour = 0;
	unsigned short coaphead = COAP_OPT_ACCESS_TOKEN_ID;

	if(VCONS_COAP == construct->type)
	{
		construct->set_code(resp, 201);
	}
	else if(VCONS_HTTP == construct->type)
	{
		construct->set_code(resp, 200);	
	}

	jsonSend = cJSON_CreateObject();

	datelist = cJSON_CreateArray();
	cJSON_AddItemToObject(jsonSend,"datelist",datelist);

	for(i = 0; i < 32; i++)
	{	
		memset(nodeName, 0, sizeof(nodeName));
		snprintf(nodeName, sizeof(nodeName), "alinkmgr_If5TimerCfg_entry%d", i);

		bzero(buffer, sizeof(buffer));
		tcapi_get(nodeName, "Enable" , buffer);
		if(atoi(buffer) == 1)
		{
			wlandate = cJSON_CreateObject();
			
			cJSON_AddBoolToObject(wlandate, "Enable", atoi(buffer));
			
			cJSON_AddNumberToObject(wlandate, "ID", i+1);

			bzero(buffer, sizeof(buffer));
			tcapi_get(nodeName, "Week" , buffer);
			if(!buffer)
			{
				snprintf(weekbuf, sizeof(weekbuf), "7,1,2,3,4,5,6");
			}
			else
			{
				week = atoi(buffer);
				_get_weeks(weekbuf, sizeof(weekbuf), week);
			}
			cJSON_AddStringToObject(wlandate, "RepeatDay", weekbuf);
			
			bzero(buffer, sizeof(buffer));
			if ( 0 == tcapi_get(nodeName, "TimeOffset" , buffer)&& 0 != buffer[0])
			{
				timeOffset = atoi(buffer);
				hour = timeOffset / 3600;
				minute = timeOffset % 3600 / 60;
				snprintf(time, sizeof(time), "%d:%d" , hour, minute);
				cJSON_AddStringToObject(wlandate, "StartTime", time);
			}

			bzero(buffer, sizeof(buffer));
			if ( 0 == tcapi_get(nodeName, "TimeOffset2" , buffer)&& 0 != buffer[0])
			{
				timeOffset = atoi(buffer);
				hour = timeOffset / 3600;
				minute = timeOffset % 3600 / 60;
				snprintf(time, sizeof(time), "%d:%d" , hour, minute);
				cJSON_AddStringToObject(wlandate, "EndTime", time);
			}
			cJSON_AddItemToArray(datelist,wlandate);		
			//cJSON_Delete(wlandate);
		}
	}

	tx_body = cJSON_PrintUnformatted(jsonSend);
	cJSON_Delete(jsonSend);
	if(VCONS_COAP == construct->type)
	{
		construct->set_header(resp, &coaphead, data_in_memory.accessToken);
		coap_set_headrespkey(construct, req, resp );
	}
	else if(VCONS_HTTP == construct->type)
	{
		construct->set_header(resp, "Content-Type", MIME_TYPE_JSON);
		construct->set_header(resp, "Content-Length", intIntoString(strlen(tx_body), slen, sizeof(slen)));
	}
	
	if(tx_body)
	{
		DBGPRINT(DEBUG_INFO, "\n\n===>>> tx_body:%s !!!\n",tx_body);
		construct->set_body(resp, tx_body, strlen(tx_body));
		free(tx_body);
	}
	return 0;
}


int  _culcalcate_weeks(char *buf )
{
    char delims[] = ",";
    char *result = NULL;
    result = strtok( buf, delims );
	int tmp,week = 0 ;
	
    while( result != NULL )
    {
		tmp = pow(2,atoi(result));
		week = week + tmp;
        printf( "result is \"%s\",week :%d \n", result ,week);
        result = strtok( NULL, delims );
    }
	return week;
}

void split(char *src,const char *separator,char **dest,int *num) 
{
     char *pNext;
     int count = 0;
     if (src == NULL || strlen(src) == 0) 
        return;
     if (separator == NULL || strlen(separator) == 0)
        return;
     pNext = (char *)strtok(src,separator); 
     while(pNext != NULL) {
          *dest++ = pNext;
          ++count;
         pNext = (char *)strtok(NULL,separator);
    }  
    *num = count;
}

int  handle_wlan_timeswitch(virtual_construct_t*construct,void*req,void*resp)
{
	char buffer[64] = {0};
	char slen[32] = {0};
	char nodeName[64] = {0};
	char *body = NULL, *tx_body = NULL;
	int body_len = 0, errcode = 0, chgflag = 0, i = 0 , Week = 0 , time1 = 0, num = 0, irand = 0,ID = 0;
	cJSON *root = NULL, *data = NULL, *jsonSend = NULL, *datelist = NULL;
	char *action = NULL, *EndTime = NULL , *StartTime = NULL, *RepeatDay = NULL;
	bool Enable = true ;
	char *revbuf[7] = {0};
	char *revbuf1[7] = {0};
	unsigned short coaphead = COAP_OPT_ACCESS_TOKEN_ID;
	time_t t;
	t = time(NULL);
	int ii = 0;
		
	if(VCONS_COAP == construct->type)
	{
		construct->set_code(resp, 201);
	}
	else if(VCONS_HTTP == construct->type)
	{
		construct->set_code(resp, 200);	
	}
	
	construct->get_body(req, &body, &body_len);
	if(body)
	{
		if(root = cJSON_Parse(body))
		{
			cJSON_GetStringByKey(root, "action", action);
						
			//cJSON_GetStringByKey(root, "data", data);
			data = cJSON_GetObjectItem(root, "data");			
			datelist = cJSON_GetObjectItem(data, "datelist");
			
			cJSON_GetIntByKey(datelist, "Enable", Enable);
			cJSON_GetStringByKey(datelist, "EndTime", EndTime);
			cJSON_GetStringByKey(datelist, "StartTime", StartTime);
			cJSON_GetIntByKey(datelist, "ID", ID);
			cJSON_GetStringByKey(datelist, "RepeatDay", RepeatDay);

			for(i = 0; i < 32; i++)//now entry num
			{	
				memset(nodeName, 0, sizeof(nodeName));
				snprintf(nodeName, sizeof(nodeName), "alinkmgr_If5TimerCfg_entry%d", i);
				bzero(buffer, sizeof(buffer));
				if ( 0 == tcapi_get(nodeName, "Enable" , buffer)&& 0 != buffer[0])
				{
					
					DBGPRINT(DEBUG_INFO, "===>>i1 :%d nodeName:%s !!!\n",i,nodeName);
					if ( atoi(buffer) != 1) break;
				}
				else
				{
					DBGPRINT(DEBUG_INFO, "===>>i1.5  Enable is NULL break.  i :%d nodeName:%s !!!\n",i,nodeName);
					break;
				}
			}
			
			DBGPRINT(DEBUG_INFO, "===>>i2 :%d !!!\n",i);
			if( ID > 32 )
			{
				DBGPRINT(DEBUG_INFO, "===>>ID more than maxnum 32 !!!\n");
				errcode = -1;
				goto send;
			}
			else
			{
				memset(nodeName, 0, sizeof(nodeName));
				snprintf(nodeName, sizeof(nodeName), "alinkmgr_If5TimerCfg_entry%d", ID);
			}

			if( !strcmp(action,"add") )
			{				
				if( EndTime && StartTime && RepeatDay )
				{
					Week = _culcalcate_weeks( RepeatDay);
					tcapi_set(nodeName, "Week" , itoa(Week));
					
					time1 = 0;
					num = 0;
					split(EndTime,":",revbuf,&num);
					if(num == 2)
					{
						time1 = atoi(revbuf[0])*3600 + atoi(revbuf[1])*60 ;
						tcapi_set(nodeName, "TimeOffset2" , itoa(time1));					
					}
					time1 = 0;
					num = 0;
					split(StartTime,":",revbuf1,&num);
					if(num == 2)
					{
						time1 = atoi(revbuf1[0])*3600 + atoi(revbuf1[1])*60 ;
						tcapi_set(nodeName, "TimeOffset2" , itoa(time1));	
					}

					if(Enable) 
					{
						tcapi_set(nodeName, "Enable" , "1");	
					} 
					else 
					{
						tcapi_set(nodeName, "Enable" , "0");	
					}

					tcapi_set(nodeName, "Action" , "ToSetHealthMode");	
					/*
					srand((int)time(NULL));
					irand = rand();
					tcapi_set(nodeName, "TaskId" , itoa(irand));
					*/
					int ii = time(&t);
					tcapi_set(nodeName, "TaskId" , itoa(ii));
					
					tcapi_set(nodeName, "Index" , "1");	
					
					chgflag = 1;
				}
			}
			else if( !strcmp(action,"delete"))
			{
				if(i >= ID )
					tcapi_unset(nodeName);
			}
			else if( !strcmp(action,"modify") || !strcmp(action,"changeState"))
			{
				if( EndTime && StartTime  && RepeatDay )
				{
					Week = _culcalcate_weeks( RepeatDay);
					DBGPRINT(DEBUG_INFO, "6.2:%s nodeName:%s ,Week:%d!!!\n",__FUNCTION__,nodeName,Week);
					tcapi_set(nodeName, "Week" , itoa(Week));					
				
					time1 = 0;
					num = 0;
					split(EndTime,":",revbuf,&num);
					if(num == 2)
					{
						time1 =atoi(revbuf[0])*3600 + atoi(revbuf[1])*60 ;		
						tcapi_set(nodeName, "TimeOffset2" , itoa(time1));					
					}
					time1 = 0;
					num = 0;
					split(StartTime,":",revbuf1,&num);
					if(num == 2)
					{
						time1 = atoi(revbuf1[0])*3600 + atoi(revbuf1[1])*60 ;			
						tcapi_set(nodeName, "TimeOffset" , itoa(time1));	
					}
				
					if(Enable) 
					{
						tcapi_set(nodeName, "Enable" , "1");	
					} 
					else 
					{
						tcapi_set(nodeName, "Enable" , "0");	
					}

					tcapi_set(nodeName, "Action" , "ToSetHealthMode");	

					/*
					srand((int)time(NULL));
					irand = rand();
					tcapi_set(nodeName, "TaskId" , itoa(irand));
					*/
					int ii = time(&t);
					tcapi_set(nodeName, "TaskId" , itoa(ii));
					
					tcapi_set(nodeName, "Index" , "1");	
					
					chgflag = 1;
				}
			}
			else
			{
				errcode = 9003 ;
			}
		}
		cJSON_Delete(root);
		//cJSON_Delete(data);
		//cJSON_Delete(datelist);
	}	
	if( chgflag == 1 )
	{
		DBGPRINT(DEBUG_INFO, "6.4:%s !!!\n",__FUNCTION__);
		tcapi_commit("alinkmgr_If5TimerCfg");
		tcapi_save();	
	}
	
send:
	jsonSend = cJSON_CreateObject();
	cJSON_AddNumberToObject(jsonSend, "errcode", errcode);
	tx_body = cJSON_PrintUnformatted(jsonSend);
	cJSON_Delete(jsonSend);
	if(VCONS_COAP == construct->type)
	{
		construct->set_header(resp, &coaphead, data_in_memory.accessToken);
		coap_set_headrespkey(construct, req, resp );
	}
	else if(VCONS_HTTP == construct->type)
	{
		construct->set_header(resp, "Content-Type", MIME_TYPE_JSON);
		construct->set_header(resp, "Content-Length", intIntoString(strlen(tx_body), slen, sizeof(slen)));
	}
	if(tx_body)
	{
		DBGPRINT(DEBUG_INFO, "tx_body:%s !!!\n",__FUNCTION__,tx_body);
		construct->set_body(resp, tx_body, strlen(tx_body));
		free(tx_body);
	}
	WF_FREE(action);
	WF_FREE(EndTime);
	WF_FREE(StartTime);
	WF_FREE(RepeatDay);
	return 0;
}


int get_guest_network(virtual_construct_t*construct,void*req,void*resp)
{
	char buffer[64] = {0};
	char WifiSsidIndex[32] = {0};
	char nodeName[32] = {0};
	char slen[32] = {0};
	char nodeNamenow[32] = {0};
	cJSON *jsonSend = NULL,*Config2g = NULL,*Config5g = NULL;
	char *tx_body = NULL;
	unsigned short coaphead = COAP_OPT_ACCESS_TOKEN_ID;

	if(VCONS_COAP == construct->type)
	{
		construct->set_code(resp, 201);
	}
	else if(VCONS_HTTP == construct->type)
	{
		construct->set_code(resp, 200);	
	}

	jsonSend = cJSON_CreateArray();

	//2.4g WifiConfig
	Config2g = cJSON_CreateObject();
	cJSON_AddItemToArray(jsonSend,Config2g);
	
	memset(nodeName, 0, sizeof(nodeName));
	snprintf(nodeName, sizeof(nodeName), "WLan_Entry3");
	
	cJSON_AddStringToObject(Config2g, "ID", nodeName);
	cJSON_AddStringToObject(Config2g, "FrequencyBand", "2.4GHz");


	bzero(buffer, sizeof(buffer));
	if ( 0 == tcapi_get(nodeName, "AuthMode" , buffer)&& 0 != buffer[0])
	{
		if(!strcmp(buffer,"OPEN"))
		{
			cJSON_AddStringToObject(Config2g, "SecOpt", "None");	
			cJSON_AddStringToObject(Config2g, "WpaPreSharedKey", "");	
		}
		else 
		{
			bzero(buffer, sizeof(buffer));
			if ( 0 == tcapi_get(nodeName, "EncrypType" , buffer)&& 0 != buffer[0])
			{
				if( !strcmp(buffer,"AES"))
				{
					cJSON_AddStringToObject(Config2g, "SecOpt", "aes");	
					bzero(buffer, sizeof(buffer));
					if ( 0 == tcapi_get(nodeName, "WPAPSK", buffer)&& 0 != buffer[0])
						cJSON_AddStringToObject(Config2g, "WpaPreSharedKey", buffer);
				}
				else 
				{
					cJSON_AddStringToObject(Config2g, "SecOpt", "tkip");	
					bzero(buffer, sizeof(buffer));
					if ( 0 == tcapi_get(nodeName, "WPAPSK", buffer)&& 0 != buffer[0])
						cJSON_AddStringToObject(Config2g, "WpaPreSharedKey", buffer);
				}			
			}
		}
	}	

	bzero(buffer, sizeof(buffer));
	if ( 0 == tcapi_get(nodeName, "EnableSSID" , buffer)&& 0 != buffer[0])
		cJSON_AddBoolToObject(Config2g, "EnableFrequency", atoi(buffer));
	
	bzero(WifiSsidIndex, sizeof(WifiSsidIndex));
	if ( 0 == tcapi_get("WebCurSet_Entry", "wlan_id", WifiSsidIndex)&& 0 != WifiSsidIndex[0])
	{
		memset(nodeNamenow, 0, sizeof(nodeNamenow));
		snprintf(nodeNamenow, sizeof(nodeNamenow), "WLan_Entry%d", atoi(WifiSsidIndex));
	}
	if( !strcmp(nodeNamenow,nodeName))
	{
		cJSON_AddNumberToObject(Config2g, "CanEnableFrequency", 0);	
	}
	else
	{
		cJSON_AddNumberToObject(Config2g, "CanEnableFrequency", 1); 
	}
	
	bzero(buffer, sizeof(buffer));
	if ( 0 == tcapi_get(nodeName, "SSID" , buffer)&& 0 != buffer[0])
		cJSON_AddStringToObject(Config2g, "WifiSsid", buffer);

	cJSON_AddNumberToObject(Config2g, "ValidTime", 3);

	cJSON_AddNumberToObject(Config2g, "RestTime", 0);


	//5g WifiConfig	
	Config5g = cJSON_CreateObject();
	cJSON_AddItemToArray(jsonSend,Config5g);
	cJSON_AddStringToObject(Config5g, "ID", nodeName);
	cJSON_AddStringToObject(Config5g, "FrequencyBand", "5GHz");

	memset(nodeName, 0, sizeof(nodeName));
	snprintf(nodeName, sizeof(nodeName), "WLan11ac_Entry3");

	bzero(buffer, sizeof(buffer));
	if ( 0 == tcapi_get(nodeName, "AuthMode" , buffer)&& 0 != buffer[0])
	{
		if(!strcmp(buffer,"OPEN"))
		{
			cJSON_AddStringToObject(Config5g, "SecOpt", "None");	
			cJSON_AddStringToObject(Config5g, "WpaPreSharedKey", "");	
		}
		else 
		{
			bzero(buffer, sizeof(buffer));
			if ( 0 == tcapi_get(nodeName, "EncrypType" , buffer)&& 0 != buffer[0])
			{
				if( !strcmp(buffer,"AES"))
				{
					cJSON_AddStringToObject(Config5g, "SecOpt", "aes");	
					bzero(buffer, sizeof(buffer));
					if ( 0 == tcapi_get(nodeName, "WPAPSK", buffer)&& 0 != buffer[0])
						cJSON_AddStringToObject(Config5g, "WpaPreSharedKey", buffer);
				}
				else 
				{
					cJSON_AddStringToObject(Config5g, "SecOpt", "tkip");	
					bzero(buffer, sizeof(buffer));
					if ( 0 == tcapi_get(nodeName, "WPAPSK", buffer)&& 0 != buffer[0])
						cJSON_AddStringToObject(Config5g, "WpaPreSharedKey", buffer);
				}			
			}
		}
	}	

	bzero(buffer, sizeof(buffer));
	if ( 0 == tcapi_get(nodeName, "EnableSSID" , buffer)&& 0 != buffer[0])
		cJSON_AddBoolToObject(Config5g, "EnableFrequency", atoi(buffer));

	bzero(WifiSsidIndex, sizeof(WifiSsidIndex));
	if ( 0 == tcapi_get("WebCurSet_Entry", "wlan_ac_id", WifiSsidIndex)&& 0 != WifiSsidIndex[0])
	{
		memset(nodeName, 0, sizeof(nodeName));
		snprintf(nodeName, sizeof(nodeName), "WLan11ac_Entry%d", atoi(WifiSsidIndex));
	}
	if( !strcmp(nodeNamenow,nodeName))
	{
		cJSON_AddNumberToObject(Config5g, "CanEnableFrequency", 0);	
	}
	else
	{
		cJSON_AddNumberToObject(Config5g, "CanEnableFrequency", 1); 
	}

	bzero(buffer, sizeof(buffer));
	if ( 0 == tcapi_get(nodeName, "SSID" , buffer)&& 0 != buffer[0])
		cJSON_AddStringToObject(Config5g, "WifiSsid", buffer);

	cJSON_AddNumberToObject(Config5g, "ValidTime", 3);
	cJSON_AddNumberToObject(Config5g, "RestTime", 0);

	tx_body = cJSON_PrintUnformatted(jsonSend);
	cJSON_Delete(jsonSend);
	if(VCONS_COAP == construct->type)
	{
		construct->set_header(resp, &coaphead, data_in_memory.accessToken);
		coap_set_headrespkey(construct, req, resp );
	}
	else if(VCONS_HTTP == construct->type)
	{
		construct->set_header(resp, "Content-Type", MIME_TYPE_JSON);
		construct->set_header(resp, "Content-Length", intIntoString(strlen(tx_body), slen, sizeof(slen)));
	}
	
	if(tx_body)
	{
		DBGPRINT(DEBUG_INFO, "tx_body:%s !!!\n",tx_body);
		construct->set_body(resp, tx_body, strlen(tx_body));
		free(tx_body);
	}
	return 0;
}

int handle_guest_network(virtual_construct_t*construct,void*req,void*resp)
{
	char buffer[64] = {0};
	char slen[32] = {0};
	char nodeName[64] = {0};
	char *body = NULL, *tx_body = NULL;
	int body_len = 0, errcode = 0, chgflag = 0,chgflag5g = 0, ValidTime2g = 3, ValidTime5g = 3;
	cJSON *root = NULL, *date = NULL, *jsonSend = NULL, *config2g = NULL, *config5g = NULL;
	char *config2g_ID = NULL, *config5g_ID = NULL , *SecOpt_5g = NULL, *SecOpt_2g = NULL, *Ssid2g = NULL,*Ssid5g = NULL,*WpaPreSharedKey2g = NULL,*WpaPreSharedKey5g = NULL;
	unsigned short coaphead = COAP_OPT_ACCESS_TOKEN_ID;
	bool config2g_enable = false;
	bool config5g_enable = false;
	
	if(VCONS_COAP == construct->type)
	{
		construct->set_code(resp, 201);
	}
	else if(VCONS_HTTP == construct->type)
	{
		construct->set_code(resp, 200);	
	}
	construct->get_body(req, &body, &body_len);
	if(body)
	{
		if(root = cJSON_Parse(body))
		{
			date = cJSON_GetObjectItem(root, "data");			
			config2g = cJSON_GetObjectItem(date, "config2g");			
			config5g = cJSON_GetObjectItem(date, "config5g");			
			if(config2g)//2.4g
			{
				cJSON_GetIntByKey(config2g, "Enable", config2g_enable);
				cJSON_GetStringByKey(config2g, "SecOpt", SecOpt_2g);
				cJSON_GetStringByKey(config2g, "WifiSsid", Ssid2g);
				cJSON_GetStringByKey(config2g, "WpaPreSharedKey", WpaPreSharedKey2g);
				cJSON_GetIntByKey(config2g, "ValidTime", ValidTime2g);

				memset(nodeName, 0, sizeof(nodeName));
				snprintf(nodeName, sizeof(nodeName), "WLan_Entry3");
				
				memset(buffer, 0, sizeof(buffer));
				tcapi_get(nodeName, "EnableSSID", buffer);
				if( atoi(buffer) != config2g_enable  )
				{
					tcapi_set(nodeName, "EnableSSID" , itoa(config2g_enable));
					chgflag = 1;
				}

				memset(buffer, 0, sizeof(buffer));
				tcapi_get(nodeName, "SSID", buffer);
				if( strcmp(buffer,Ssid2g) )
				{
					tcapi_set(nodeName, "SSID" , Ssid2g);
					chgflag = 1;
				}

				if( !strcmp(SecOpt_2g,"none"))
				{
					bzero(buffer, sizeof(buffer));
					tcapi_get(nodeName, "AuthMode" , buffer);
					if( strcmp(buffer,"OPEN") )
					{
						tcapi_set(nodeName, "AuthMode" , "OPEN");
						chgflag = 1;
					}					
				}
				else if( !strcmp(SecOpt_2g,"aes"))
				{
					bzero(buffer, sizeof(buffer));
					tcapi_get(nodeName, "EncrypType" , buffer);
					if( strcmp(buffer,"AES"))
					{
						tcapi_set(nodeName, "EncrypType" , "AES");
						chgflag = 1;
					}	
					memset(buffer, 0, sizeof(buffer));
					tcapi_get(nodeName, "WPAPSK", buffer);
					if( strcmp(buffer, WpaPreSharedKey2g) )
					{
						tcapi_set(nodeName, "WPAPSK" , WpaPreSharedKey2g);
						chgflag = 1;
					}
				}
				else if( !strcmp(SecOpt_2g,"tkip"))
				{
					bzero(buffer, sizeof(buffer));
					tcapi_get(nodeName, "EncrypType" , buffer);
					if( strcmp(buffer,"TKIP"))
					{
						tcapi_set(nodeName, "EncrypType" , "TKIP");
						chgflag = 1;
					}		
					memset(buffer, 0, sizeof(buffer));
					tcapi_get(nodeName, "WPAPSK", buffer);
					if( strcmp(buffer, WpaPreSharedKey2g) )
					{
						tcapi_set(nodeName, "WPAPSK" , WpaPreSharedKey2g);
						chgflag = 1;
					}
				}

				if(chgflag == 1 )
				{
					tcapi_set(nodeName, "wlan_changed", "1");
					DBGPRINT(DEBUG_INFO, "WLan commit !!!\n");
					tcapi_commit("WLan");
				}
			}	
			else
			{
				DBGPRINT(DEBUG_INFO,"2g error !!! ===========>\n");						
				errcode = -1;
				goto send;
			}
			
			//5g
			if( config5g)
			{
				cJSON_GetIntByKey(config5g, "Enable", config5g_enable);
				cJSON_GetStringByKey(config5g, "SecOpt", SecOpt_5g);
				cJSON_GetStringByKey(config5g, "WifiSsid", Ssid5g);
				cJSON_GetStringByKey(config5g, "WpaPreSharedKey", WpaPreSharedKey5g);
				cJSON_GetStringByKey(config5g, "ValidTime", ValidTime5g);

				memset(nodeName, 0, sizeof(nodeName));
				snprintf(nodeName, sizeof(nodeName), "WLan11ac_Entry3");
				
				memset(buffer, 0, sizeof(buffer));
				tcapi_get(nodeName, "EnableSSID", buffer);
				if( atoi(buffer) != config5g_enable  )
				{
					tcapi_set(nodeName, "EnableSSID" , itoa(config5g_enable));
					chgflag5g = 1;
				}

				memset(buffer, 0, sizeof(buffer));
				tcapi_get(nodeName, "SSID", buffer);
				if( strcmp(buffer,Ssid5g) )
				{
					tcapi_set(nodeName, "SSID" , Ssid5g);
					chgflag5g = 1;
				}

				if( !strcmp(SecOpt_5g,"none"))
				{
					bzero(buffer, sizeof(buffer));
					tcapi_get(nodeName, "AuthMode" , buffer);
					if( strcmp(buffer,"OPEN") )
					{
						tcapi_set(nodeName, "AuthMode" , "OPEN");
						chgflag5g = 1;
					}					
				}
				else if( !strcmp(SecOpt_5g,"aes"))
				{
					bzero(buffer, sizeof(buffer));
					tcapi_get(nodeName, "EncrypType" , buffer);
					if( strcmp(buffer,"AES"))
					{
						tcapi_set(nodeName, "EncrypType" , "AES");
						tcapi_set(nodeName, "WPAPSK" , WpaPreSharedKey5g);
						chgflag5g = 1;
					}		
				}
				else if( !strcmp(SecOpt_5g,"tkip"))
				{
					bzero(buffer, sizeof(buffer));
					tcapi_get(nodeName, "EncrypType" , buffer);
					if( strcmp(buffer,"TKIP"))
					{
						tcapi_set(nodeName, "EncrypType" , "TKIP");
						tcapi_set(nodeName, "WPAPSK" , WpaPreSharedKey5g);
						chgflag5g = 1;
					}		
				}
				
				if(chgflag5g == 1 )
				{
					DBGPRINT(DEBUG_INFO, "WLan11ac commit !!!\n");
					tcapi_set(nodeName, "wlan_changed", "1");
					tcapi_commit("WLan11ac");
				}
			}
			/*else
			{
				DBGPRINT(DEBUG_INFO,"5g error !!! ===========>\n");						
				errcode = -1;
				goto send;
			}*/

			if(chgflag == 1 || chgflag5g == 1 )
			{
				DBGPRINT(DEBUG_INFO, "tcapi_save !!!\n");
				tcapi_save();		
			}
		}
		cJSON_Delete(root);
	}
send:	
	jsonSend = cJSON_CreateObject();
	cJSON_AddNumberToObject(jsonSend, "errcode", errcode);
	tx_body = cJSON_PrintUnformatted(jsonSend);
	cJSON_Delete(jsonSend);
	if(VCONS_COAP == construct->type)
	{
		construct->set_header(resp, &coaphead, data_in_memory.accessToken);
		coap_set_headrespkey(construct, req, resp );
	}
	else if(VCONS_HTTP == construct->type)
	{
		construct->set_header(resp, "Content-Type", MIME_TYPE_JSON);
		construct->set_header(resp, "Content-Length", intIntoString(strlen(tx_body), slen, sizeof(slen)));
	}
	
	if(tx_body)
	{
		DBGPRINT(DEBUG_INFO, "tx_body:%s !!!\n",__FUNCTION__,tx_body);
		construct->set_body(resp, tx_body, strlen(tx_body));
		free(tx_body);
	}
	WF_FREE(config2g_ID);
	WF_FREE(config5g_ID);
	WF_FREE(SecOpt_5g);
	WF_FREE(SecOpt_2g);
	WF_FREE(Ssid2g);
	WF_FREE(Ssid5g);
	WF_FREE(WpaPreSharedKey2g);
	WF_FREE(WpaPreSharedKey5g);
	return 0;
}

int get_wan(virtual_construct_t*construct,void*req,void*resp)
{
	struct sysinfo info;
	cJSON *jsonSend = NULL;
	char *tx_body = NULL;
	char buffer[64] = {0};
	char tmp[64] = {0};
	char slen[32] = {0};
	unsigned short coaphead = COAP_OPT_ACCESS_TOKEN_ID;

	if(VCONS_COAP == construct->type)
	{
		construct->set_code(resp, 201);
	}
	else if(VCONS_HTTP == construct->type)
	{
		construct->set_code(resp, 200);	
		construct->set_header(resp, "Content-Type", MIME_TYPE_JSON);
	}

	jsonSend = cJSON_CreateObject();

	cJSON_AddStringToObject(jsonSend, "ID", "waninfo_Common");

	bzero(buffer, sizeof(buffer));
	bzero(tmp, sizeof(tmp));
	if ( 0 == tcapi_get("waninfo_Common", "CurAPMode", buffer)&& 0 != buffer[0] && 0 == tcapi_get("waninfo_Common", "CycleValue_9", tmp)&& 0 != tmp[0])
	{
		if( !strcmp(buffer, "Route") && !strcmp(tmp, "PPPoE") )
		{
			bzero(buffer, sizeof(buffer));
			bzero(tmp, sizeof(tmp));
			tcapi_get("waninfo_wanIF", "USERNAME", buffer);
			tcapi_get("waninfo_wanIF", "PASSWORD", tmp);
			cJSON_AddStringToObject(jsonSend, "Username", buffer);
			cJSON_AddStringToObject(jsonSend, "Password", tmp);				
		}
		else
		{
			cJSON_AddStringToObject(jsonSend, "Username", "");
			cJSON_AddStringToObject(jsonSend, "Password", "");	
		}
	}

	bzero(buffer, sizeof(buffer));
	if ( 0 == tcapi_get("waninfo_Common", "CurAPMode", buffer)&& 0 != buffer[0])
	{
		if ( 0 == strcmp(buffer, "Bridge") )
		{		
			cJSON_AddStringToObject(jsonSend, "ConnectionType", "Bridged");
		}
		else if( 0 == strcmp(buffer, "Route"))
		{
			bzero(tmp, sizeof(tmp));
			tcapi_get("waninfo_Common", "CycleValue_9", tmp);
			if ( 0 == strcmp(tmp, "DHCP") )
			{		
				cJSON_AddStringToObject(jsonSend, "ConnectionType", "IP_Routed"); 				
			}
			else if( 0 == strcmp(tmp, "PPPoE"))
			{
				cJSON_AddStringToObject(jsonSend, "ConnectionType", "PPP_Routed");
				
				cJSON_AddNumberToObject(jsonSend, "X_SpeDialMode", 0);

				bzero(tmp, sizeof(tmp));
				tcapi_get("waninfo_wanIF", "MTU", tmp);
				cJSON_AddNumberToObject(jsonSend, "MRU", atoi(tmp));
			}
 		}
		
		if(!strcmp(buffer, "Route") || !strcmp(buffer, "Bridge"))
			cJSON_AddStringToObject(jsonSend, "AccessType", "Ethernet");	
	}
	
	bzero(buffer, sizeof(buffer));
	if ( 0 == tcapi_get("waninfo_Common", "EthernetState", buffer)&& 0 != buffer[0])
	{
		cJSON_AddStringToObject(jsonSend, "AccessStatus", buffer);	
		if (!strcmp(buffer, "up"))
		{
			cJSON_AddStringToObject(jsonSend, "ConnectionStatus", "Connected");		
		}
		else
		{
			cJSON_AddStringToObject(jsonSend, "ConnectionStatus", "Disconnected"); 	
		}
	}

	bzero(buffer, sizeof(buffer));
	if ( 0 == tcapi_get("waninfo_Common", "CycleValue_4", buffer)&& 0 != buffer[0])
	{
		if(!strcmp(buffer, "Enable"))
		{
			cJSON_AddNumberToObject(jsonSend, "NATType", 2);
		}
		else if(!strcmp(buffer, "Disabled"))
		{
			cJSON_AddNumberToObject(jsonSend, "NATType", 1);
		}
	}

	bzero(buffer, sizeof(buffer));
	if ( 0 == tcapi_get("waninfo_Common", "CycleValue_10", buffer)&& 0 != buffer[0])
	{
		cJSON_AddStringToObject(jsonSend, "IPv4DnsServers", buffer);
	}

	cJSON_AddBoolToObject(jsonSend, "Enable", 1);

	bzero(buffer, sizeof(buffer));
	if ( 0 == tcapi_get("waninfo_Common", "CycleValue_8", buffer)&& 0 != buffer[0])
	{
		cJSON_AddStringToObject(jsonSend, "IPv4Addr", buffer);
	}

	cJSON_AddStringToObject(jsonSend, "ServiceList", "INTERNET");

	bzero(buffer, sizeof(buffer));
	if ( 0 == tcapi_get("waninfo_PVC", "VLANID", buffer)&& 0 != buffer[0])
	{
		cJSON_AddStringToObject(jsonSend, "LowerLayer", buffer);
	}

	bzero(buffer, sizeof(buffer));
	if ( 0 == tcapi_get("waninfo_wanIF", "MTU", buffer)&& 0 != buffer[0])
	{
		cJSON_AddStringToObject(jsonSend, "MTU", buffer);
	}

	if ( 0 == tcapi_get("waninfo_Common", "CurAPMode", buffer)&& 0 != buffer[0] && 0 == tcapi_get("waninfo_Common", "CycleValue_9", tmp)&& 0 != tmp[0])
	{
		if( !strcmp(buffer, "Route") )
		{
			if( !strcmp(tmp, "DHCP") )
			{
				cJSON_AddStringToObject(jsonSend, "IPv4AddrType", "DHCP");	
			}
			else if(  !strcmp(tmp, "Static"))
			{
				cJSON_AddStringToObject(jsonSend, "IPv4AddrType", "Static");
			}
		}	
	}

	bzero(buffer, sizeof(buffer));
	if ( 0 == tcapi_get("waninfo_Entry", "NetMask", buffer)&& 0 != buffer[0])
	{
		cJSON_AddStringToObject(jsonSend, "IPv4Mask", buffer);
	}

	bzero(buffer, sizeof(buffer));
	if ( 0 == tcapi_get("waninfo_Entry", "GateWay", buffer)&& 0 != buffer[0])
	{
		cJSON_AddStringToObject(jsonSend, "IPv4Gateway", buffer);
	}
	
	bzero(buffer, sizeof(buffer));
	if ( 0 == tcapi_get("waninfo_Entry", "GUIInterfaceName", buffer)&& 0 != buffer[0])
	{
		cJSON_AddStringToObject(jsonSend, "Alias", buffer);
		cJSON_AddStringToObject(jsonSend, "Name", buffer);
	}

	bzero(buffer, sizeof(buffer));
	if ( 0 == tcapi_get("waninfo_wanIF", "IFName", buffer)&& 0 != buffer[0])
	{
		cJSON_AddStringToObject(jsonSend, "PPPoEServiceName", buffer);
	}

	bzero(buffer, sizeof(buffer));
	if ( 0 == tcapi_get("waninfo_wanIF", "PPPGETIP", buffer)&& 0 != buffer[0])
	{	
		if( !strcmp(buffer, "Dynamic") )
		{
			cJSON_AddStringToObject(jsonSend, "PPPAuthMode", "AUTO");
		}
		else
		{
			cJSON_AddStringToObject(jsonSend, "PPPAuthMode", buffer);	
		}
	}

	cJSON_AddBoolToObject(jsonSend, "MACColoneEnable", 0);

	cJSON_AddStringToObject(jsonSend, "MACColone", "");
	
	cJSON_AddNumberToObject(jsonSend, "MSS", 0);

	cJSON_AddNumberToObject(jsonSend, "PPPIdletime", 30);

	tx_body = cJSON_PrintUnformatted(jsonSend);
	cJSON_Delete(jsonSend);
	if(VCONS_COAP == construct->type)
	{
		construct->set_header(resp, &coaphead, data_in_memory.accessToken);
		coap_set_headrespkey(construct, req, resp );
	}
	else if(VCONS_HTTP == construct->type)
	{
		construct->set_header(resp, "Content-Type", MIME_TYPE_JSON);
		construct->set_header(resp, "Content-Length", intIntoString(strlen(tx_body), slen, sizeof(slen)));
	}
	
	if(tx_body)
	{
		DBGPRINT(DEBUG_INFO, "tx_body:%s !!!\n",tx_body);
		construct->set_body(resp, tx_body, strlen(tx_body));
		free(tx_body);
	}
	return 0;
}


int handle_reboot(virtual_construct_t*construct,void*req,void*resp)
{
	char  *tx_body = NULL;
	char slen[32] = {0};
	int body_len = 0;
	cJSON  *jsonSend = NULL;
	int errcode = 0 ;	
	unsigned short coaphead = COAP_OPT_ACCESS_TOKEN_ID;
	
	if(VCONS_COAP == construct->type)
	{
		construct->set_code(resp, 201);
	}
	else if(VCONS_HTTP == construct->type)
	{
		construct->set_code(resp, 200);	
	}
	
	jsonSend = cJSON_CreateObject();
	cJSON_AddNumberToObject(jsonSend, "errcode", errcode);
	tx_body = cJSON_PrintUnformatted(jsonSend);
	cJSON_Delete(jsonSend);
	
	if(VCONS_COAP == construct->type)
	{
		construct->set_header(resp, &coaphead, data_in_memory.accessToken);
		coap_set_headrespkey(construct, req, resp );
	}
	else if(VCONS_HTTP == construct->type)
	{
		construct->set_header(resp, "Content-Type", MIME_TYPE_JSON);
		construct->set_header(resp, "Content-Length", intIntoString(strlen(tx_body), slen, sizeof(slen)));
	}
	
	if(tx_body)
	{
		construct->set_body(resp, tx_body, strlen(tx_body));
		free(tx_body);
	}
	system("reboot -d 5 &");		
	return 0;
}

int handle_restore(virtual_construct_t*construct,void*req,void*resp)
{
	char  *tx_body = NULL;
	char slen[32] = {0};
	int body_len = 0;
	cJSON  *jsonSend = NULL;
	int errcode = 0 ;	
	unsigned short coaphead = COAP_OPT_ACCESS_TOKEN_ID;
	
	if(VCONS_COAP == construct->type)
	{
		construct->set_code(resp, 201);
	}
	else if(VCONS_HTTP == construct->type)
	{
		construct->set_code(resp, 200);	
	}

	jsonSend = cJSON_CreateObject();
	cJSON_AddNumberToObject(jsonSend, "errcode", errcode);
	tx_body = cJSON_PrintUnformatted(jsonSend);
	cJSON_Delete(jsonSend);
	
	if(VCONS_COAP == construct->type)
	{
		construct->set_header(resp, &coaphead, data_in_memory.accessToken);
		coap_set_headrespkey(construct, req, resp );
	}
	else if(VCONS_HTTP == construct->type)
	{
		construct->set_header(resp, "Content-Type", MIME_TYPE_JSON);
		construct->set_header(resp, "Content-Length", intIntoString(strlen(tx_body), slen, sizeof(slen)));
	}
	if(tx_body)
	{
		construct->set_body(resp, tx_body, strlen(tx_body));
		free(tx_body);
	}
	
	_cfg_func_setObject("devId", "");
	_cfg_func_setObject("secret", "");
	_cfg_func_setObject("psk", "");
	_cfg_func_setObject("activiated", "0");
	tcapi_save();	
	//stop_coap_client(&g_wflink_ctx.coapClient);
	enqueue_state_machine(st, STATE_WAITACTIVATE);

	system("prolinecmd restore default &");	
	
	return 0;
}

int handle_delDevice(virtual_construct_t*construct,void*req,void*resp)
{
	char  *tx_body = NULL;
	char slen[32] = {0};
	int body_len = 0;
	cJSON  *jsonSend = NULL;
	int errcode = 0 ;	
	unsigned short coaphead = COAP_OPT_ACCESS_TOKEN_ID;
	
	if(VCONS_COAP == construct->type)
	{
		construct->set_code(resp, 201);
	}
	else if(VCONS_HTTP == construct->type)
	{
		construct->set_code(resp, 200);	
	}
	
	jsonSend = cJSON_CreateObject();
	cJSON_AddNumberToObject(jsonSend, "errcode", errcode);
	tx_body = cJSON_PrintUnformatted(jsonSend);
	cJSON_Delete(jsonSend);
	
	if(VCONS_COAP == construct->type)
	{
		construct->set_header(resp, &coaphead, data_in_memory.accessToken);
		coap_set_headrespkey(construct, req, resp );
	}
	else if(VCONS_HTTP == construct->type)
	{
		construct->set_header(resp, "Content-Type", MIME_TYPE_JSON);
		construct->set_header(resp, "Content-Length", intIntoString(strlen(tx_body), slen, sizeof(slen)));
	}
	
	if(tx_body)
	{
		DBGPRINT(DEBUG_INFO, "tx_body:%s !!!\n",tx_body);
		construct->set_body(resp, tx_body, strlen(tx_body));
		free(tx_body);
	}

	_cfg_func_setObject("devId", "");
	_cfg_func_setObject("secret", "");
	_cfg_func_setObject("psk", "");
	_cfg_func_setObject("activiated", "0");
	tcapi_save();
//	stop_coap_client(&g_wflink_ctx.coapClient);
	enqueue_state_machine(st, STATE_WAITACTIVATE);

	DBGPRINT(DEBUG_INFO, "handle_delDevice end !!!\n");
		
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
		.route = "ntwk/wandiagnose",
		.process[REQUEST_METHOD_GET] = get_wandiagnose ,
		.process[REQUEST_METHOD_POST] = NULL,
	},
	{
		.route = "system/HostInfo",
		.process[REQUEST_METHOD_GET] = get_HostInfo,
		.process[REQUEST_METHOD_POST] = NULL,
	},
	{
		.route = "system/changedevicename",
		.process[REQUEST_METHOD_GET] = NULL,
		.process[REQUEST_METHOD_POST] = handle_change_devicename,
	},
	{
		.route = "system/deviceinfo",
		.process[REQUEST_METHOD_GET] = get_deviceinfo ,
		.process[REQUEST_METHOD_POST] = NULL,
	},
	{
		.route = "ntwk/lan_host",
		.process[REQUEST_METHOD_GET] = get_lan_host ,
		.process[REQUEST_METHOD_POST] = NULL,
	},
	{
		.route = "app/qosclass_host",
		.process[REQUEST_METHOD_GET] = NULL ,
		.process[REQUEST_METHOD_POST] = handle_qosclass_host,
	},
	{
		.route = "ntwk/WlanBasic",
		.process[REQUEST_METHOD_GET] = get_WlanBasic ,
		.process[REQUEST_METHOD_POST] = handle_WlanBasic,
	},
	{
		.route = "ntwk/WlanGuideBasic",
		.process[REQUEST_METHOD_GET] = NULL ,
		.process[REQUEST_METHOD_POST] = handle_WlanGuideBasic,
	},	
	{
		.route = "ntwk/wlanfilterenhance",
		.process[REQUEST_METHOD_GET] = get_wlan_filterenhance ,
		.process[REQUEST_METHOD_POST] = handle_wlan_filterenhance,
	},
	{
		.route = "ntwk/wlantimeswitch",
		.process[REQUEST_METHOD_GET] = get_wlan_timeswitch ,
		.process[REQUEST_METHOD_POST] = handle_wlan_timeswitch,
	},
	{
		.route = "ntwk/guest_network",
		.process[REQUEST_METHOD_GET] = get_guest_network ,
		.process[REQUEST_METHOD_POST] = handle_guest_network,
	},
	{
		.route = "ntwk/wan",
		.process[REQUEST_METHOD_GET] = get_wan ,
		.process[REQUEST_METHOD_POST] = NULL,
	},
	{
		.route = "service/reboot.cgi",
		.process[REQUEST_METHOD_GET] = NULL ,
		.process[REQUEST_METHOD_POST] = handle_reboot,
	},
	{
		.route = "service/restoredefcfg.cgi",
		.process[REQUEST_METHOD_GET] = NULL ,
		.process[REQUEST_METHOD_POST] = handle_restore,
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
	{
		.route = ".sys/delDevice",
		.process[REQUEST_METHOD_GET] = NULL ,
		.process[REQUEST_METHOD_POST] = handle_delDevice,
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
		
		DBGPRINT(DEBUG_INFO, "\n\n  =====>>>>  route = %s iroute:%s\n", route,iroute);
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
	cJSON *data = NULL,*array_data = NULL;
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
		array_data = cJSON_CreateArray();
		xcoap_sync(data);
		cJSON_AddItemToArray(array_data,data);
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
	
	if(array_data)
	{
		body = cJSON_PrintUnformatted(array_data);
		cJSON_Delete(array_data);
	}
	else
	{
		body = cJSON_PrintUnformatted(data);
		cJSON_Delete(data);	
	}

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
	usleep(1000*1000);//wait deldev interface send finished,then stop tcp.
	stop_coap_client(&g_wflink_ctx.coapClient);
	DBGPRINT(DEBUG_INFO, "end\n");
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
							_cfg_func_setObject("devId", "");
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
