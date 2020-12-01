#ifndef COAP_CLIENT_H__
#define COAP_CLIENT_H__

#include "wflink.h"

//mv into coap2/pdu.h
//#define COAP_OPT_ACCESS_TOKEN_ID 2049
//#define COAP_OPT_REQ_ID 2050
//#define COAP_OPT_DEV_ID 2051
//#define COAP_OPT_USER_ID 2052

#define COAP_RESPONSE_TIMEOUT_SEC 10
#define RETRANSMISSION_INTERVAL_SEC 10
#define COAP_HEARTBEAT_INTERVAL_SEC 50

#define DISCONNECT_FLAG (1 << 17)
#define RELOGIN_FLAG (1 << 16)
#define TIMEOUT_FLAG 0xffff

#define COAP_REGISTER_URI "/.sys/register"
#define COAP_ACTIVATE_URI "/.sys/activate"
#define COAP_LOGIN_URI "/.sys/login"
#define COAP_SYNC_URI "/.sys/devInfoSync"
#define COAP_HEARTBEAT_URI "/.sys/heartbeat"
#define COAP_REFRESH_URI "/.sys/refresh"
#define COAP_INACTIVATE_URI "/.sys/delDevice"

enum coap_client_state_e
{
	STATE_INIT,
	STATE_PREPARE,
	STATE_CONN,	//register or login
	STATE_SYNC,
	STATE_HEARTBT,
	STATE_WAITACTIVATE,
	STATE_ACTIVATE,
	STATE_MAX,
};

enum coap_client_error_code_e
{
	// rx errcode
	CEC_SUCCESS = 0,
	CEC_OTHERS = 1,
	CEC_DEVREGISTED = 2,
	CEC_REGISTERCODE_EXPIRE = 3,
	CEC_REGISTERINFO_NOMATCH = 4,
	CEC_LOGINPWD_NOMATCH = 5,
	CEC_DEVDELETED = 6,	// unbind dev
	CEC_ACCESSTOKEN_EXPIRE = 1002,
	CEC_REFRESHTOKEN_EXPIRE = 1006,
	CEC_DEVNONEXISTENT = 1403,
	CEC_OPTIONTOKEN_MISS = 4996,
	CEC_ARGUMENT_INCOMPLETED = 4998,
	CEC_INTERNAL = 4999,
	// tx errcode
	CEC_ROUTER_INTERNAL = 5002,
	CEC_PLATFORM_ISSUE = 5003,
};

int start_coap_client_state_machine(void *args);
int init_coap_client(void);
void *start_coap_client(void *args);
int stop_coap_client(void *args);
void *create_coap_request_transaction(method_type_e method, char *uri_str, char *text, int noreply_max);
int send_coap_request(void *coap_client, void *vtrans);
int get_coap_server_address(char *dst, int size);
int get_coap_transport(void);
int set_options_access_token(void *vtrans, char *access_token);
extern int stop_coap_client_and_reinit(void);
extern int start_relogin(void);

#endif
