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
#include <sys/epoll.h>
#include <sys/wait.h>
#include "stddef.h"
#include <pthread.h>
#include <time.h>
#include <signal.h>
#include <poll.h>
#include <cJSON.h>

#include "wflink.h"
#include "wflink_utility.h"
#include "socket_thread.h"
#include "libhttpd.h"
#include "app_client_session.h"
#include "http_server.h"

void wflink_msg_internal_free(wflink_msg_t *msg)
{
	int i = 0;
	 if(msg)
	 {
	 	if(msg->isTx)
 		{
 			//firstline info is constant
 			WF_FREE(msg->protocol);
			for(i = 0; i < msg->header.lines; i++)
			{
				WF_FREE(msg->header.line[i].key);
				WF_FREE(msg->header.line[i].val);
			}
			WF_FREE(msg->bodyPtr);	
 		}
		else
		{
			WF_FREE(msg->src);
			if(msg->pvt)
			{
				httpd_pvt_internal_free(msg->pvt);
				free(msg->pvt);
			}
		}
	 }
}

/*************************************************************
 *                  Virtual Constructors start
 *************************************************************/

int http_set_code(void *msg, int code)
{
	wflink_msg_t *resp = (wflink_msg_t *)msg;
	resp->isResponse = true;
	resp->firstLine.res.status = code;
	resp->firstLine.res.detail = get_status_code_details(code);
	return 0;
}
int http_get_header(void *msg, char *key, char **value)
{
	wflink_msg_t *resp = (wflink_msg_t *)msg;
	if(key && value)
	{
		*value = get_head(&resp->header, key);
		if(*value)
			return strlen(*value);
		return -1;
	}
	return -1;
}
int http_set_header(void *msg, char *key, char *value)
{
	wflink_msg_t *resp = (wflink_msg_t *)msg;
	if(key&&strlen(key)&&value&&strlen(value)&&resp->header.lines<sizeof(resp->header.line)/sizeof(resp->header.line[0]))
	{
		resp->header.line[resp->header.lines].key = strdup(key);
		resp->header.line[resp->header.lines].val = strdup(value);
		resp->header.lines++;
		return 0;
	}
	return -1;
}
int http_get_body(void *msg, char **value, int *len)
{
	wflink_msg_t *resp = (wflink_msg_t *)msg;
	if(value && len)
	{
		*value = resp->bodyPtr;
		*len = resp->bodyLen;
	}
}
int http_set_body(void *msg, char *value, int len)
{
	wflink_msg_t *resp = (wflink_msg_t *)msg;
	if(value&&len>0)
	{
		resp->bodyPtr = malloc(len);
		memcpy(resp->bodyPtr, value, len);
		resp->bodyLen = len;
		return 0;
	}
	return -1;
}

virtual_construct_t g_http_constructor =
{
	.type = VCONS_HTTP,
	.set_code = http_set_code,
	.get_header = http_get_header,
	.set_header = http_set_header,
	.get_body = http_get_body,
	.set_body = http_set_body
};
/*************************************************************
 *                  Virtual Constructors end
 *************************************************************/

#define CSRF_TOKEN_LEN 32

static char g_csrf_token[64] = {0};
static sig_mutex_t g_csrf_token_lock;

int set_g_csrf_token(void)
{
	// 32bytes composed of character and number
	sig_mutex_lock(&g_csrf_token_lock);
	genRandomString(g_csrf_token, CSRF_TOKEN_LEN+1);
	sig_mutex_unlock(&g_csrf_token_lock);
	return 0;
}
int get_g_csrf_token(char *dst, int size)
{
	if(!dst || size < sizeof(g_csrf_token))
		return -1;
	sig_mutex_lock(&g_csrf_token_lock);
	strncpy(dst, g_csrf_token, size);
	sig_mutex_unlock(&g_csrf_token_lock);
	return 0;
}
int is_csrf_token_match(wflink_msg_t *req)
{
	char *content_type = NULL;
	cJSON *body = NULL, *csrf = NULL, *csrf_param = NULL, *csrf_token = NULL;
	char cur_csrf_token[64] = {0};
	if(req->firstLine.req.method == REQUEST_METHOD_POST && 
		(!strncmp(req->firstLine.req.route, HTTP_DISCOVERY1_URI, strlen(HTTP_DISCOVERY1_URI)) || 
			!strncmp(req->firstLine.req.route, HTTP_DISCOVERY2_URI, strlen(HTTP_DISCOVERY2_URI)) || 
			!strncmp(req->firstLine.req.route, HTTP_ACTIVATE_URI, strlen(HTTP_ACTIVATE_URI))
		)
	)
	{
		http_get_header(req, "Content-Type", &content_type);
		if(!content_type || !strncasecmp(content_type, MIME_TYPE_JSON, strlen(MIME_TYPE_JSON)))
		{
			body = cJSON_Parse(req->bodyPtr);
			if(!body)
			{
				DBGPRINT(DEBUG_ERROR, "handle csrf error [parse json failed]!\n");
				goto no_match;
			}
			csrf = cJSON_GetObjectItem(body, "csrf");
			if(!csrf)
			{
				DBGPRINT(DEBUG_ERROR, "handle csrf error [no item named csrf]!\n");
				goto no_match;
			}
			csrf_token = cJSON_GetObjectItem(csrf, "csrf_token");
			if(!csrf_token || csrf_token->type != cJSON_String)
			{
				DBGPRINT(DEBUG_ERROR, "handle csrf error [no item named csrf_token or value type error]!\n");
				goto no_match;
			}
			get_g_csrf_token(cur_csrf_token, sizeof(cur_csrf_token));
			DBGPRINT(DEBUG_TRACE, "cur_csrf_token = %s, csrf_token = %s\n", cur_csrf_token, csrf_token->valuestring);
			if(strlen(csrf_token->valuestring) && strncmp(cur_csrf_token, csrf_token->valuestring, strlen(csrf_token->valuestring)))
			{
				DBGPRINT(DEBUG_ERROR, "handle csrf error [csrf_token not match]!\n");
				goto no_match;
			}
		}
		else if(content_type && !strncasecmp(content_type, "application/x-www-form-urlencoded", 33))
		{
			// not support now
		}
		else if(content_type && !strncasecmp(content_type, "multipart/form-data", 19))
		{
			// not support now
		}
		else
		{
		}
	}
	return 0;
no_match:
	return -1;
}

void init_csrf_info(void)
{
	sig_mutex_init(&g_csrf_token_lock, NULL);
	set_g_csrf_token();
}

int csrf_response_error(wflink_msg_t *tx)
{
	char cur_csrf_token[64] = {0};
	char slen[32] = {0};
	char *body = NULL;
	cJSON *jsonSend = cJSON_CreateObject();
	if(!jsonSend)
		return -1;
	set_g_csrf_token();
	get_g_csrf_token(cur_csrf_token, sizeof(cur_csrf_token));
	cJSON_AddStringToObject(jsonSend, "csrf_param", "authenticity_token");
	cJSON_AddStringToObject(jsonSend, "csrf_token", cur_csrf_token);
	//cJSON_AddNumberToObject(jsonSend, "errcode", HEC_APP_NOLOGIN);
	cJSON_AddNumberToObject(jsonSend, "err", 1);
	body = cJSON_PrintUnformatted(jsonSend);
	cJSON_Delete(jsonSend);
	if(body)
	{
		http_set_code(tx, 200);	
		http_set_header(tx, "Content-Type", MIME_TYPE_JSON);
		http_set_header(tx, "Content-Length", intIntoString(strlen(body), slen, sizeof(slen)));
		http_set_body(tx, body, strlen(body));
		free(body);
	}
	return 0;
}

/* Parse msg into structure
 * Light process in recving process
 */
int handle_rx(wflink_msg_t*rx,char*buf,int len,wflink_msg_t*tx)
{
	rx->isResponse = false;
	rx->isTx = false;
	rx->srcLen = len;
	rx->src = malloc(len);
	rx->pvt = malloc(sizeof(libhttpd_pvt));
	memcpy(rx->src, buf, len);
	memset(rx->pvt, 0, sizeof(libhttpd_pvt));
	if(!rx->isResponse && !rx->isTx)
 	{
 		tx->isResponse = true;
		tx->isTx = true;
 		return httpd_parse_request(rx->src,len,rx,tx);
 	}
	return -1;
}

/* Parse msg into structure
 * Light process in recving process
 */
int build_tx(wflink_msg_t*tx)
{
	int init_size = 4096;
	int row = 0;
	if(!tx->isTx || !tx->isResponse)
		return -1;
	tx->src = malloc(init_size);
	memset(tx->src, 0, init_size);
	tx->srcLen += snprintf(tx->src+tx->srcLen, init_size-tx->srcLen, "%s %d %s\r\n", tx->protocol, tx->firstLine.res.status, tx->firstLine.res.detail);
	for(row = 0; row < tx->header.lines; row++)
	{
		tx->srcLen += snprintf(tx->src+tx->srcLen, init_size-tx->srcLen, "%s: %s\r\n", tx->header.line[row].key, tx->header.line[row].val);
	}
	if(tx->bodyPtr && tx->bodyLen)
	{
		tx->srcLen += snprintf(tx->src+tx->srcLen, init_size-tx->srcLen, "\r\n");
		if(tx->bodyLen > (init_size - tx->srcLen))
		{
			tx->src = realloc(tx->src, tx->srcLen + tx->bodyLen);
		}
		memcpy(tx->src+tx->srcLen, tx->bodyPtr, tx->bodyLen);
		tx->srcLen += tx->bodyLen;
	}
	return 0;
}

/* Call interface
 * Real process in the threadpool
 */
int process_msg(char*buf,int len,char*args)
{
	 int i = 0;
	 int ret = -1;
	 wflink_msg_t* req = NULL;
	 wflink_msg_t resp_tmp;
	 wflink_msg_t* resp = &resp_tmp;
	 method_type_e method = REQUEST_METHOD_GET;
	 char *route = NULL, iroute = NULL;
	 sig_lock_t *rw_lock = NULL;
	 int (**processes)(virtual_construct_t*construct,void*req,void*resp) = NULL;
	 int (*process)(virtual_construct_t*construct,void*req,void*resp) = NULL;
	 if(!buf || !args || len != sizeof(wflink_msg_t))
	 {
		 return -1;
	 }
	 req = (wflink_msg_t*)buf;
	 method = req->firstLine.req.method;
	 route = req->firstLine.req.route;
	 if(req->isResponse || !route)
	 {
		 return -1;
	 }
#if 1
	 memset(resp, 0, sizeof(*resp));
	 resp->isResponse = true;
	 resp->isTx = true;
	 resp->protocol = strdup(req->protocol);
	 resp->firstLine.res.status = 200;
	 resp->firstLine.res.detail= get_status_code_details(200);
	 ret = do_process_by_route(route, method, &g_http_constructor, req, resp);
	 DBGPRINT(DEBUG_TRACE, "do_process_by_route return %d\n", ret);
	 if(!ret)
	 {
		 build_tx(resp);
		 send_response(resp, args);
	 }
	 else
	 {
		 http_set_code(resp, 404);
		 http_set_header(resp, "Content-Type", "text/html");
		 http_set_header(resp, "Content-Length", "13");
		 http_set_body(resp, "Hello Wflink!", strlen("Hello Wflink!"));
		 build_tx(resp);
		 send_response(resp, args);
	 }
	 wflink_msg_internal_free(resp);
#else
	 for(i = 0; i < sizeof(g_interfaces)/sizeof(g_interfaces[0]); i++)
	 {
		 sig_mutex_lock(&g_interfaces[i].lock);
		 iroute = g_interfaces[i].route;
		 rw_lock = &g_interfaces[i].s_lock;
		 processes = &g_interfaces[i].process;
		 sig_mutex_unlock(&g_interfaces[i].lock);
		 if(!strncmp(route, iroute, strlen(iroute)))
		 {
			 process = processes[method];
			 if(process)
			 {
				 memset(resp, 0, sizeof(*resp));
				 resp->isResponse = true;
				 resp->isTx = true;
				 resp->protocol = strdup(req->protocol);
				 resp->firstLine.res.status = 200;
				 resp->firstLine.res.detail= get_status_code_details(200);
				 (REQUEST_METHOD_GET == method) ? sig_lock_read(rw_lock) : sig_lock_rw(rw_lock);
				 ret = process(&g_http_constructor,(void *)req, (void *)resp);
				 sig_unlock_rw(rw_lock);
				 if(!ret)
				 {
					 build_tx(resp);
					 send_response(resp, args);
				 }
				 wflink_msg_internal_free(resp);
			 }
			 break;
		 }
	 }
#endif
	 wflink_msg_internal_free(req);
	 return ret;
}

int send_response(wflink_msg_t *tx, void *args)
{
	int ret = -1;
	if(tx->src && tx->srcLen)
	{
		DBGPRINT(DEBUG_TRACE, "[%d]<==\n%s\n\n", tx->srcLen, tx->src);
		ret = conn_send(args, tx->src, tx->srcLen);
		//conn_close(args, NULL);
	}
	return ret;
}

int handle_request(char*buf,int len,void*args)
{
	int ret = 0;
	void *list_conn = NULL;
	wflink_msg_t rx, tx;
	struct socket_t *conn = (struct socket_t *)args;
	sig_mutex_lock(&conn->lock);
	list_conn = conn->pool;
	sig_mutex_unlock(&conn->lock);
	void *thread_pool = list_conn_get_pool(list_conn);
	/* if ret < 0, server will disconnect automatically 
	 * rx info is stored in rx.src, all points in the structure point to the position in rx.src so that memory free is easy
	 * tx info consists of discrete memories, all points in the structure need to free when tx release
	 * rx/tx release see function wflink_msg_internal_free()
	 */
	DBGPRINT(DEBUG_TRACE, "[%d]==>\n%s\n\n", len, buf);
	memset(&rx, 0, sizeof(rx));
	memset(&tx, 0, sizeof(tx));
	ret = handle_rx(&rx,buf,len,&tx);
	if(0 == ret)
	{
		ret = is_csrf_token_match(&rx);
		if(0 == ret)
		{
			/* push to thread queue */
			ret = add_task_pool(thread_pool,(char*)&rx,sizeof(rx),args,process_msg);
			if(ret)
			{
				// add task into pthread pool failed
			}
		}
		else
		{
			// csrf_token is not matched
			csrf_response_error(&tx);
			build_tx(&tx);
			send_response(&tx, args);
		}
	}
	else
	{
		// http resolve failed
		build_tx(&tx);
		send_response(&tx, args);
	}
	if(ret)
	{
		wflink_msg_internal_free(&rx);
		wflink_msg_internal_free(&tx);
	}
	return ret;
}

int start_http_server(wflink_context_t *app, wflink_cfg_t *cfg)
{
	int ret = 0;
	void *list_conn = NULL;
	init_csrf_info();
	app_client_ctx_init(MAX_LOGIN_ACCOUNT);
	list_conn = create_list_conn(app->maxConn, app->threadPool);
	if(!list_conn)
	{
		DBGPRINT(DEBUG_ERROR, "create connPool fail!\n");
		return -1;
	}
	/* If args login exists, the server can send welcome to the new connection */
	/* If args read_do is NULL, the default read functino will be used, the max buffer size is 4096 */
	ret = tcp_server_listening(list_conn, cfg->http.bind_server_address, cfg->http.bind_server_port, HTTP_SERVER_WORKMODE, NULL, NULL, handle_request);
	if(ret < 0)
	{
		DBGPRINT(DEBUG_ERROR, "create httpServer fail!\n");
		return -1;
	}
	return 0;
}

