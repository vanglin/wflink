#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include <cJSON.h>

#include "wflink.h"
#include "wflink_utility.h"


#ifdef ONLY_FOR_COMPILE
int _cfg_func_getObject(char *item, void *value, int bufsize){return 0;}
int _cfg_func_setObject(char *item, void *value){return 0;}
int _getWorkMode(void){return 1;}
char *_getDeivceIpAddr(char *buffer, int buflen, int workmode, char *deft)
{
	// coap client bind ip address
	snprintf(buffer, buflen, "%s", "192.168.10.1");
	return buffer;
}
int xcoap_register(cJSON *jsonSend, char *role){
	cJSON_AddStringToObject(jsonSend, "mac", "00:E0:FC:01:80:08");
	cJSON_AddStringToObject(jsonSend, "sn", "00E0FC018008");
	cJSON_AddStringToObject(jsonSend, "vendor", "NSB");
	cJSON_AddStringToObject(jsonSend, "model", "HA030WC");
	cJSON_AddStringToObject(jsonSend, "from", role);
	return 0;
}
int xcoap_login(cJSON *jsonSend){return 0;}
int xcoap_sync(cJSON *jsonSend){return 0;}
int xcoap_activate(cJSON *jsonSend, char *registerCode){return 0;}
int xcoap_heartbeat(cJSON *jsonSend){return 0;}
#else
#include "libtcapi.h"

#define getValueFromCfgmgr(buffer,node,attr)	\
	bzero(buffer, sizeof(buffer));	\
	if ( 0 == tcapi_get(node, attr, buffer)	\
		&& 0 != buffer[0] )

cJSON *_get_devInfo(void);

int getIntFromCfgmgr(char *node, char *attr, int deft)
{
	char buffer[256] = {0};
	int value = deft;
	getValueFromCfgmgr(buffer, node, attr)
	{
		value = atoi(buffer);
	}
	return value;
}
char *getStringFromCfgmgr(char *buffer, int buflen, char *node, char *attr, char *deft)
{
	if(buffer)
	{
		bzero(buffer, buflen);
		if ( 0 != tcapi_get(node, attr, buffer)
			|| 0 == buffer[0] )
		{
			snprintf(buffer, buflen, "%s", deft);
		}
		return buffer;
	}
	return deft;
}

int _cfg_func_getObject(char *item, void *value, int bufsize)
{
	memset(value, 0, bufsize);
	return tcapi_get("alinkmgr_cuc", item, value);
}

int _cfg_func_setObject(char *item, void *value)
{
	return tcapi_set("alinkmgr_cuc", item, value);
}

int _getWorkMode(void)
{
	char buffer[256] = {0};
	char fixedmode[16] = {0};
	char curmode[16] = {0};
	int workmode = 0;
	bzero(buffer, sizeof(buffer));
	if ( 0 == tcapi_get("APWanInfo_Common", "FixedAPMode", buffer) && 0 != buffer[0] )
	{
		snprintf(fixedmode, sizeof(fixedmode), "%s", buffer);
	}
	bzero(buffer, sizeof(buffer));
	if ( 0 == tcapi_get("Waninfo_Common", "CurAPMode", buffer) && 0 != buffer[0] )
	{
		snprintf(curmode, sizeof(curmode), "%s", buffer);
	}
	if(!strcmp(curmode, "Bridge"))
		workmode = 0;
	else if(!strcmp(curmode, "Route"))
		workmode = 1;
	else if(!strcmp(curmode, "APClient"))
		workmode = 2;
	else if(!strcmp(fixedmode, "Bridge"))
		workmode = 0;
	else if(!strcmp(fixedmode, "Route"))
		workmode = 1;
	else if(!strcmp(fixedmode, "APClient"))
		workmode = 2;
	else
		workmode = 0;
	return workmode;
}

char *_getDeivceIpAddr(char *buffer, int buflen, int workmode, char *deft)
{
	if(buffer)
	{
		bzero(buffer, sizeof(buffer));
		// Route mode
		if(1 == workmode)
		{
			getStringFromCfgmgr(buffer, buflen, "WanInfo_Entry0", "IP", deft);
		}
		else
		{
			getStringFromCfgmgr(buffer, buflen, "APWanInfo_Entry0", "IP", deft);
		}
		return buffer;
	}
	return deft;
}

int xcoap_register(cJSON *jsonSend, char *role)
{
	char buffer[256] = {0};
	char br0_mac[20] = {0};
	char sn15[16] = {0};
	get_interface_hwaddr("br0", br0_mac, sizeof(br0_mac));
	stringToCapital(br0_mac);
	mac_add_dot(br0_mac, buffer);
	cJSON_AddStringToObject(jsonSend, "mac", buffer);
	getValueFromCfgmgr(buffer, "DeviceInfo_devParaDynamic", "ManufacturerOUI")
	{
		strcat(sn15, buffer);
		getValueFromCfgmgr(buffer, "DeviceInfo_devParaDynamic", "SerialNum")
		{
			strcat(sn15, buffer);
			cJSON_AddStringToObject(jsonSend, "sn", sn15);
		}
	}
	getValueFromCfgmgr(buffer, "DeviceInfo_devParaStatic", "Manufacturer")
	{
		cJSON_AddStringToObject(jsonSend, "vendor", buffer);
	}
	getValueFromCfgmgr(buffer, "DeviceInfo_devParaStatic", "ModelName")
	{
		cJSON_AddStringToObject(jsonSend, "model", buffer);
	}
	cJSON_AddStringToObject(jsonSend, "from", role);
	return 0;
}

int xcoap_login(cJSON *jsonSend)
{
	char devId[64] = {0}, secret[64] = {0};
	_cfg_func_getObject("devId", devId, sizeof(devId));
	_cfg_func_getObject("secret", secret, sizeof(secret));
	cJSON_AddStringToObject(jsonSend, "devId", devId);
	cJSON_AddStringToObject(jsonSend, "secret", secret);
	return 0;
}

int xcoap_sync(cJSON *jsonSend)
{
	char devId[64] = {0};
	cJSON *devInfo = _get_devInfo();
	_cfg_func_getObject("devId", devId, sizeof(devId));
	cJSON_AddStringToObject(jsonSend, "devId", devId);
	cJSON_AddItemToObject(jsonSend, "devInfo", devInfo);
	return 0;
}

int xcoap_activate(cJSON *jsonSend, char *registerCode)
{
	cJSON *devInfo = _get_devInfo();
	cJSON_AddStringToObject(jsonSend, "code", registerCode);
	cJSON_AddItemToObject(jsonSend, "devInfo", devInfo);
	return 0;
}

int xcoap_heartbeat(cJSON *jsonSend)
{
	char ts[64] = {0};
	time_t timer;
	struct tm *time_fields;
	timer = time(NULL);
	time_fields = localtime(&timer);
	snprintf(ts, sizeof(ts), "%04d%02d%02dT%02d%02d%02dZ", time_fields->tm_year+1900, time_fields->tm_mon+1, time_fields->tm_mday,
		time_fields->tm_hour, time_fields->tm_min, time_fields->tm_sec);
	cJSON_AddStringToObject(jsonSend, "ts", ts);
	return 0;
}

cJSON *_get_devInfo(void)
{
	char buffer[256] = {0};
	char br0_mac[20] = {0};
	char sn15[16] = {0}, manu[16] = {0}, devType[16] = {0};
	cJSON *devInfo = cJSON_CreateObject();
	if(devInfo)
	{
		getValueFromCfgmgr(buffer, "DeviceInfo_devParaDynamic", "ManufacturerOUI")
		{
			strncpy(manu, buffer, 2);
			snprintf(devType, sizeof(devType), "%s", buffer + 2);
			strcat(sn15, buffer);
			getValueFromCfgmgr(buffer, "DeviceInfo_devParaDynamic", "SerialNum")
			{
				strcat(sn15, buffer);
			}
		}
		cJSON_AddStringToObject(devInfo, "sn", sn15);
		getValueFromCfgmgr(buffer, "DeviceInfo_devParaStatic", "ModelName")
		{
			cJSON_AddStringToObject(devInfo, "model", buffer);
		}
		cJSON_AddStringToObject(devInfo, "devType", devType);
		cJSON_AddStringToObject(devInfo, "manu", manu);
		cJSON_AddStringToObject(devInfo, "prodId", "000b");// !!! fake prodId
		get_interface_hwaddr("br0", br0_mac, sizeof(br0_mac));
		stringToCapital(br0_mac);
		mac_add_dot(br0_mac, buffer);
		cJSON_AddStringToObject(devInfo, "mac", buffer);
		getValueFromCfgmgr(buffer, "DeviceInfo_devParaStatic", "CustomerHWVersion")
		{
			cJSON_AddStringToObject(devInfo, "hwv", buffer);
		}
		getValueFromCfgmgr(buffer, "DeviceInfo_devParaStatic", "CustomerSWVersion")
		{
			cJSON_AddStringToObject(devInfo, "swv", buffer);
		}
		cJSON_AddNumberToObject(devInfo, "protType", 1);
	}
	return devInfo;
}
#endif

