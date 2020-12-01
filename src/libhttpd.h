#ifndef __LIBHTTPD_H__
#define __LIBHTTPD_H__

#include "string_utils.h"

typedef struct
{
	int mime_flag;
	int one_one;
	char *encodedurl;
	char *reqhost;
    char *decodedurl;
	char *origfilename;
	char *query;
}libhttpd_pvt;

int httpd_parse_request(char*buf,int len,wflink_msg_t*rx,wflink_msg_t*tx);
void httpd_pvt_internal_free(void *pvt);
char *get_status_code_details(int status);

#endif
