#ifndef __HTTP_SERVER_H__
#define __HTTP_SERVER_H__

#include "wflink.h"
#include "wflink_config.h"

#define HTTP_SERVER_ADDRESS "192.168.195.129"
#define HTTP_SERVER_PORT 8089
#define HTTP_SERVER_WORKMODE 0x00

#define HTTP_DISCOVERY1_URI "/api/system/user_login_nonce"
#define HTTP_DISCOVERY2_URI "/api/system/user_login_proof"
#define HTTP_ACTIVATE_URI "/api/shp/verifycode"

#define MIME_TYPE_JSON "application/json"

enum http_server_error_code_e
{
	HEC_SUCCESS = 0,
	HEC_ARGUMENT_VALUE = 9003,
	HEC_OVER_SIZE = 9004,
	HEC_ARGUMENT_NAME = 9005,
	HEC_APP_NOLOGIN = 10003,
};

int start_http_server(wflink_context_t *app, wflink_cfg_t *cfg);
int set_g_csrf_token(void);
int get_g_csrf_token(char *dst, int size);

#endif
