#ifndef __WFLINK_H__
#define __WFLINK_H__

#include <stdbool.h>
#include "sig_utils.h"
#include "string_utils.h"
#include "wflink_logs.h"

//typedef int bool;
#define true 1
#define false 0

#define WF_FREE(p) if(p)free(p)
#define WF_VNAME(v) (#v)

typedef enum
{
	REQUEST_METHOD_GET,
	REQUEST_METHOD_POST,
	REQUEST_METHOD_PUT,
	REQUEST_METHOD_DELETE,
	REQUEST_METHOD_MAX
}method_type_e;

typedef enum
{
	PROTO_WiFi = 1,
	PROTO_ZWave,
	PROTO_ZigBee,
	PROTO_BLE
}protType_e;

typedef enum
{
	VCONS_HTTP,
	VCONS_COAP,
}vconstruct_type_e;

typedef struct
{
	sig_mutex_t lock;
	sig_cond_t cond;
	void *session;
	pthread_t pid;
}coap_client_t;

typedef struct
{
	//app system arguments
	int maxConn;
	int maxThread;
	void *threadPool;
	void *htimer;
	char *appname;
	char *cfgfilename;

#if 0
	//dev info for register/login
	char *devMac;
	char *devSn;
	char *vendor;
	char *model;
	char *devType;
	char *manu;
	char *prodId;
	char *hwv;	//hardware version
	char *swv;	//software version
	protType_e protType;
	
	//work info
	char *workMode;
	char *workRole;
	char *localIPAddr;
	char *externalIPAddr;
#endif

	//http server obj
	void *httpServer;
	//coap client obj
	coap_client_t coapClient;
}wflink_context_t;

typedef struct
{
	method_type_e method;
	char *route;
}request_line_t;

typedef struct
{
	int  status;
	char *detail;
}response_line_t;

typedef struct
{
	bool isResponse;
	bool isTx;
	union
	{
		request_line_t req;
		response_line_t res;
	}firstLine;
	char *protocol;
	struct line_t header;
	int bodyLen;
	char *bodyPtr;
	int srcLen;
	char *src;
	void *pvt;
}wflink_msg_t;

typedef struct
{
	vconstruct_type_e type;
	int (*set_code)(void *msg, int code);
	int (*get_header)(void *msg, char *key, char **value);
	int (*set_header)(void *msg, char *key, char *value);
	int (*get_body)(void *msg, char **value, int *len);
	int (*set_body)(void *msg, char *value, int len);
}virtual_construct_t;

typedef int (*msg_process)(virtual_construct_t*construct,void*req,void*resp);

/* msg process */
void interfaces_init();
int do_process_by_route(char *route, method_type_e method, virtual_construct_t *construct, void *req, void *resp);
void iterate_processors(char *route, int (*callback)(void *processor, void *args), void *args);
char *get_processor_property_route(void *arg, int need_lock);
msg_process *get_processor_property_process(void *arg, int need_lock);
int platform_services_process(char*buf,int len,char*args);

#endif
