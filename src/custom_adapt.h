#ifndef __CUSTOM_ADAPT_H__
#define __CUSTOM_ADAPT_H__

#include <cJSON.h>
/* Used for local store
 * function get/set activiated,devId,secret,psk
 *
 * Node in config looks like the below:
 *   <alinkmgr>
 *     <cuc activiated="0" devId="" secret="" psk="" />
 *   </alinkmgr>
 * restore into factory will reset it as above.
 *
 *   bool activiated;	//login condition
 *   char *devId;	//login username
 *   char *secret;	//login password
 *   char *psk;		//reserved
 */

int _cfg_func_getObject(char *item, void *value, int bufsize);
int _cfg_func_setObject(char *item, void *value);
int _getWorkMode(void);
char *_getDeivceIpAddr(char *buffer, int buflen, int workmode, char *deft);
int xcoap_register(cJSON *jsonSend, char *role);
int xcoap_login(cJSON *jsonSend);
int xcoap_sync(cJSON *jsonSend);
int xcoap_activate(cJSON *jsonSend, char *registerCode);
int xcoap_heartbeat(cJSON *jsonSend);

#endif
