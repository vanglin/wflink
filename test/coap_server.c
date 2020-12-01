/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 * -*- */

/* coap -- simple implementation of the Constrained Application Protocol (CoAP)
 *         as defined in RFC 7252
 *
 * Copyright (C) 2010--2016 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <signal.h>
#ifdef _WIN32
#define strcasecmp _stricmp
#include "getopt.c"
#else
#include <unistd.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <dirent.h>
#endif

#include "coap2/coap.h"

#include "cJSON.h"
#include "start_pid.h"

#define COAP_RESOURCE_CHECK_TIME 2

#ifndef min
#define min(a,b) ((a) < (b) ? (a) : (b))
#endif

/* temporary storage for dynamic resource representations */
static int quit = 0;

/* changeable clock base (see handle_put_time()) */
static time_t clock_offset;
static time_t my_clock_base = 0;

struct coap_resource_t *time_resource = NULL;

#ifndef WITHOUT_ASYNC
/* This variable is used to mimic long-running tasks that require
 * asynchronous responses. */
static coap_async_state_t *async = NULL;
#endif /* WITHOUT_ASYNC */

#ifdef __GNUC__
#define UNUSED_PARAM __attribute__ ((unused))
#else /* not a GCC */
#define UNUSED_PARAM
#endif /* GCC */

/* SIGINT handler: set quit to 1 for graceful termination */
static void
handle_sigint(int signum UNUSED_PARAM) {
  quit = 1;
}

#define INDEX "This is a test server made with libcoap (see https://libcoap.net)\n" \
              "Copyright (C) 2010--2016 Olaf Bergmann <bergmann@tzi.org>\n\n"

static void
hnd_get_index(coap_context_t *ctx UNUSED_PARAM,
              struct coap_resource_t *resource UNUSED_PARAM,
              coap_session_t *session UNUSED_PARAM,
              coap_pdu_t *request UNUSED_PARAM,
              coap_binary_t *token UNUSED_PARAM,
              coap_string_t *query UNUSED_PARAM,
              coap_pdu_t *response) {
  unsigned char buf[3];

  response->code = COAP_RESPONSE_CODE(205);

  coap_add_option(response,
                  COAP_OPTION_CONTENT_TYPE,
                  coap_encode_var_safe(buf, sizeof(buf), COAP_MEDIATYPE_TEXT_PLAIN), buf);

  coap_add_option(response,
                  COAP_OPTION_MAXAGE,
                  coap_encode_var_safe(buf, sizeof(buf), 0x2ffff), buf);

  coap_add_data(response, strlen(INDEX), (unsigned char *)INDEX);
}

static void
hnd_get_time(coap_context_t  *ctx,
             struct coap_resource_t *resource,
             coap_session_t *session,
             coap_pdu_t *request,
             coap_binary_t *token,
             coap_string_t *query,
             coap_pdu_t *response) {
  unsigned char buf[40];
  size_t len;
  time_t now;
  coap_tick_t t;
  (void)request;

  /* FIXME: return time, e.g. in human-readable by default and ticks
   * when query ?ticks is given. */

  /* if my_clock_base was deleted, we pretend to have no such resource */
  response->code =
    my_clock_base ? COAP_RESPONSE_CODE(205) : COAP_RESPONSE_CODE(404);

  if (coap_find_observer(resource, session, token)) {
    coap_add_option(response,
                    COAP_OPTION_OBSERVE,
                    coap_encode_var_safe(buf, sizeof(buf), resource->observe), buf);
  }

  if (my_clock_base)
    coap_add_option(response,
                    COAP_OPTION_CONTENT_FORMAT,
                    coap_encode_var_safe(buf, sizeof(buf), COAP_MEDIATYPE_TEXT_PLAIN), buf);

  coap_add_option(response,
                  COAP_OPTION_MAXAGE,
                  coap_encode_var_safe(buf, sizeof(buf), 0x01), buf);

  if (my_clock_base) {

    /* calculate current time */
    coap_ticks(&t);
    now = my_clock_base + (t / COAP_TICKS_PER_SECOND);

    if (query != NULL
        && memcmp(query->s, "ticks", min(5, query->length)) == 0) {
          /* output ticks */
          len = snprintf((char *)buf, sizeof(buf), "%u", (unsigned int)now);
          coap_add_data(response, len, buf);

    } else {      /* output human-readable time */
      struct tm *tmp;
      tmp = gmtime(&now);
      len = strftime((char *)buf, sizeof(buf), "%b %d %H:%M:%S", tmp);
      coap_add_data(response, len, buf);
    }
  }
}

static void
hnd_put_time(coap_context_t *ctx UNUSED_PARAM,
             struct coap_resource_t *resource,
             coap_session_t *session UNUSED_PARAM,
             coap_pdu_t *request,
             coap_binary_t *token UNUSED_PARAM,
             coap_string_t *query UNUSED_PARAM,
             coap_pdu_t *response) {
  coap_tick_t t;
  size_t size;
  unsigned char *data;

  /* FIXME: re-set my_clock_base to clock_offset if my_clock_base == 0
   * and request is empty. When not empty, set to value in request payload
   * (insist on query ?ticks). Return Created or Ok.
   */

  /* if my_clock_base was deleted, we pretend to have no such resource */
  response->code =
    my_clock_base ? COAP_RESPONSE_CODE(204) : COAP_RESPONSE_CODE(201);

  coap_resource_notify_observers(resource, NULL);

  /* coap_get_data() sets size to 0 on error */
  (void)coap_get_data(request, &size, &data);

  if (size == 0)        /* re-init */
    my_clock_base = clock_offset;
  else {
    my_clock_base = 0;
    coap_ticks(&t);
    while(size--)
      my_clock_base = my_clock_base * 10 + *data++;
    my_clock_base -= t / COAP_TICKS_PER_SECOND;
  }
}

static void
hnd_delete_time(coap_context_t *ctx UNUSED_PARAM,
                struct coap_resource_t *resource UNUSED_PARAM,
                coap_session_t *session UNUSED_PARAM,
                coap_pdu_t *request UNUSED_PARAM,
                coap_binary_t *token UNUSED_PARAM,
                coap_string_t *query UNUSED_PARAM,
                coap_pdu_t *response UNUSED_PARAM) {
  my_clock_base = 0;    /* mark clock as "deleted" */

  /* type = request->hdr->type == COAP_MESSAGE_CON  */
  /*   ? COAP_MESSAGE_ACK : COAP_MESSAGE_NON; */
}

#ifndef WITHOUT_ASYNC
static void
hnd_get_async(coap_context_t *ctx,
              struct coap_resource_t *resource UNUSED_PARAM,
              coap_session_t *session,
              coap_pdu_t *request,
              coap_binary_t *token UNUSED_PARAM,
              coap_string_t *query UNUSED_PARAM,
              coap_pdu_t *response) {
  unsigned long delay = 5;
  size_t size;

  if (async) {
    if (async->id != request->tid) {
      coap_opt_filter_t f;
      coap_option_filter_clear(f);
      response->code = COAP_RESPONSE_CODE(503);
    }
    return;
  }

  if (query) {
    unsigned char *p = query->s;

    delay = 0;
    for (size = query->length; size; --size, ++p)
      delay = delay * 10 + (*p - '0');
  }

  async = coap_register_async(ctx,
                              session,
                              request,
                              COAP_ASYNC_SEPARATE | COAP_ASYNC_CONFIRM,
                              (void *)(COAP_TICKS_PER_SECOND * delay));
}

static void
check_async(coap_context_t *ctx,
            coap_tick_t now) {
  coap_pdu_t *response;
  coap_async_state_t *tmp;

  size_t size = 13;

  if (!async || now < async->created + (unsigned long)async->appdata)
    return;

  response = coap_pdu_init(async->flags & COAP_ASYNC_CONFIRM
             ? COAP_MESSAGE_CON
             : COAP_MESSAGE_NON,
             COAP_RESPONSE_CODE(205), 0, size);
  if (!response) {
    coap_log(LOG_DEBUG, "check_async: insufficient memory, we'll try later\n");
    async->appdata =
      (void *)((unsigned long)async->appdata + 15 * COAP_TICKS_PER_SECOND);
    return;
  }

  response->tid = coap_new_message_id(async->session);

  if (async->tokenlen)
    coap_add_token(response, async->tokenlen, async->token);

  coap_add_data(response, 4, (unsigned char *)"done");

  if (coap_send(async->session, response) == COAP_INVALID_TID) {
    coap_log(LOG_DEBUG, "check_async: cannot send response for message\n");
  }
  coap_remove_async(ctx, async->session, async->id, &tmp);
  coap_free_async(async);
  async = NULL;
}
#endif /* WITHOUT_ASYNC */

static void
init_resources(coap_context_t *ctx) {
  coap_resource_t *r;

  r = coap_resource_init(NULL, 0);
  coap_register_handler(r, COAP_REQUEST_GET, hnd_get_index);
  
  coap_add_attr(r, coap_make_str_const("ct"), coap_make_str_const("0"), 0);
  coap_add_attr(r, coap_make_str_const("title"), coap_make_str_const("\"General Info\""), 0);
  coap_add_resource(ctx, r);

  /* store clock base to use in /time */
  my_clock_base = clock_offset;
  r = coap_resource_init(coap_make_str_const("time"), COAP_RESOURCE_FLAGS_NOTIFY_CON);
  coap_register_handler(r, COAP_REQUEST_GET, hnd_get_time);
  coap_register_handler(r, COAP_REQUEST_PUT, hnd_put_time);
  coap_register_handler(r, COAP_REQUEST_DELETE, hnd_delete_time);

  coap_add_attr(r, coap_make_str_const("ct"), coap_make_str_const("0"), 0);
  coap_add_attr(r, coap_make_str_const("title"), coap_make_str_const("\"General Info\""), 0);
  coap_add_attr(r, coap_make_str_const("rt"), coap_make_str_const("\"Ticks\""), 0);
  r->observable = 1;
  coap_add_attr(r, coap_make_str_const("if"), coap_make_str_const("\"clock\""), 0);

  coap_add_resource(ctx, r);
  time_resource = r;

#ifndef WITHOUT_ASYNC
  r = coap_resource_init(coap_make_str_const("async"), 0);
  coap_register_handler(r, COAP_REQUEST_GET, hnd_get_async);

  coap_add_attr(r, coap_make_str_const("ct"), coap_make_str_const("0"), 0);
  coap_add_resource(ctx, r);
#endif /* WITHOUT_ASYNC */
}

static void
fill_keystore(coap_context_t *ctx) {
  static uint8_t key[] = "secretPSK";
  size_t key_len = sizeof( key ) - 1;
  coap_context_set_psk( ctx, "CoAP", key, key_len );
}

static void
usage( const char *program, const char *version) {
  const char *p;

  p = strrchr( program, '/' );
  if ( p )
    program = ++p;

  fprintf( stderr, "%s v%s -- a small CoAP implementation\n"
     "(c) 2010,2011,2015 Olaf Bergmann <bergmann@tzi.org>\n\n"
     "usage: %s [-A address] [-p port]\n\n"
     "\t-A address\tinterface address to bind to\n"
     "\t-g group\tjoin the given multicast group\n"
     "\t-p port\t\tlisten on specified port\n"
     "\t-v num\t\tverbosity level (default: 3)\n"
     "\t-l list\t\tFail to send some datagram specified by a comma separated list of number or number intervals(for debugging only)\n"
     "\t-l loss%%\t\tRandmoly fail to send datagrams with the specified probability(for debugging only)\n",
    program, version, program );
}

static coap_context_t *
get_context(const char *node, const char *port) {
  coap_context_t *ctx = NULL;
  int s;
  struct addrinfo hints;
  struct addrinfo *result, *rp;

  ctx = coap_new_context(NULL);
  if (!ctx) {
    return NULL;
  }
  /* Need PSK set up before we set up (D)TLS endpoints */
  fill_keystore(ctx);

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
  hints.ai_socktype = SOCK_DGRAM; /* Coap uses UDP */
  hints.ai_flags = AI_PASSIVE | AI_NUMERICHOST;

  s = getaddrinfo(node, port, &hints, &result);
  if ( s != 0 ) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
    coap_free_context(ctx);
    return NULL;
  }

  /* iterate through results until success */
  for (rp = result; rp != NULL; rp = rp->ai_next) {
    coap_address_t addr, addrs;
    coap_endpoint_t *ep_udp = NULL, *ep_dtls = NULL, *ep_tcp = NULL, *ep_tls = NULL;

    if (rp->ai_addrlen <= sizeof(addr.addr)) {
      coap_address_init(&addr);
      addr.size = rp->ai_addrlen;
      memcpy(&addr.addr, rp->ai_addr, rp->ai_addrlen);
      addrs = addr;
      if (addr.addr.sa.sa_family == AF_INET) {
        addrs.addr.sin.sin_port = htons(ntohs(addr.addr.sin.sin_port) + 1);
      } else if (addr.addr.sa.sa_family == AF_INET6) {
        addrs.addr.sin6.sin6_port = htons(ntohs(addr.addr.sin6.sin6_port) + 1);
      } else {
        goto finish;
      }

      ep_udp = coap_new_endpoint(ctx, &addr, COAP_PROTO_UDP);
      if (ep_udp) {	  	
	coap_log(LOG_CRIT, "coap_dtls_is_supported():%d\n",coap_dtls_is_supported());	
	if (coap_dtls_is_supported()) {
	  ep_dtls = coap_new_endpoint(ctx, &addrs, COAP_PROTO_DTLS);
	  if (!ep_dtls)
	    coap_log(LOG_CRIT, "cannot create DTLS endpoint\n");
	}
      } else {
        coap_log(LOG_CRIT, "cannot create UDP endpoint\n");
        continue;
      }
      ep_tcp = coap_new_endpoint(ctx, &addr, COAP_PROTO_TCP);
      if (ep_tcp) {	  	
	coap_log(LOG_CRIT, "coap_tls_is_supported():%d\n",coap_tls_is_supported());	
	if (coap_tls_is_supported()) {
	  ep_tls = coap_new_endpoint(ctx, &addrs, COAP_PROTO_TLS);
	  if (!ep_tls)
	    coap_log(LOG_CRIT, "cannot create TLS endpoint\n");
	}
      } else {
        coap_log(LOG_CRIT, "cannot create TCP endpoint\n");
      }
      if (ep_udp)
	goto finish;
    }
  }

  fprintf(stderr, "no context available for interface '%s'\n", node);

finish:
  freeaddrinfo(result);
  return ctx;
}

typedef unsigned char method_t;

static coap_pdu_t *
coap_new_request(coap_context_t *ctx,
                 coap_session_t *session,
                 method_t method,
                 coap_optlist_t **options,
                 unsigned char *data,
                 size_t length,
                 coap_string_t the_token) {
  coap_pdu_t *pdu;
  (void)ctx;

  if (!(pdu = coap_new_pdu(session)))
    return NULL;

  pdu->type = COAP_MESSAGE_CON;
  pdu->tid = coap_new_message_id(session);
  pdu->code = method;

  pdu->token_length = (uint8_t)the_token.length;
  if ( !coap_add_token(pdu, the_token.length, the_token.s)) {
    coap_log(LOG_DEBUG,"cannot add token to request\n");
  }

  coap_add_optlist_pdu(pdu, options);

  if (length) {
    coap_add_data(pdu, length, data);
  }

  return pdu;
}

char addr_str[NI_MAXHOST] = "0.0.0.0";
char port_str[NI_MAXSERV] = "5683";
coap_log_t log_level = LOG_WARNING;
char *appame = NULL;
char *group = NULL;
coap_context_t  *g_ctx = NULL;

#define cJSON_GetIntByKey(src, name, dst)	\
	do {	\
		cJSON *tmp = cJSON_GetObjectItem(src, name);	\
		if(!tmp)	\
			break;	\
		else if(tmp->type == cJSON_True)	\
			dst = 1;	\
		else if(tmp->type == cJSON_False)	\
			dst = 0;	\
		else if(tmp->type == cJSON_Number)	\
			dst = tmp->valueint;	\
	}while(0)

#define cJSON_GetFloatByKey(src, name, dst)	\
	do {	\
		cJSON *tmp = cJSON_GetObjectItem(src, name);	\
		if(!tmp)	\
			break;	\
		else if(tmp->type == cJSON_Number)	\
			dst = (float)tmp->valuedouble;	\
	}while(0)

#define cJSON_GetDoubleByKey(src, name, dst)	\
	do {	\
		cJSON *tmp = cJSON_GetObjectItem(src, name);	\
		if(!tmp)	\
			break;	\
		else if(tmp->type == cJSON_Number) \
			dst = tmp->valuedouble;	\
	}while(0)

#define cJSON_GetStringByKey(src, name, dst)	\
	do {	\
		cJSON *tmp = cJSON_GetObjectItem(src, name);	\
		if(!tmp)	\
			break;	\
		else if(tmp->type == cJSON_String)	\
			if(tmp->valuestring)	\
			{	\
				while (*tmp->valuestring && *tmp->valuestring < 33)	\
					tmp->valuestring++;	\
				dst = strdup(tmp->valuestring); \
			}	\
	}while(0)

int extra_option(char ch,char*optarg)
{
	switch (ch) {
    case 'A' :
      strncpy(addr_str, optarg, NI_MAXHOST-1);
      addr_str[NI_MAXHOST - 1] = '\0';
      break;
    case 'g' :
      group = optarg;
      break;
    case 'p' :
      strncpy(port_str, optarg, NI_MAXSERV-1);
      port_str[NI_MAXSERV - 1] = '\0';
      break;
    case 'v' :
      log_level = strtol(optarg, NULL, 10);
      break;
    case 'l':
      if (!coap_debug_set_packet_loss(optarg)) {
	usage(appame, LIBCOAP_PACKAGE_VERSION);
	exit(1);
      }
      break;
    default:
      usage( appame, LIBCOAP_PACKAGE_VERSION );
      exit( 1 );
    }
	return 0;
}

int cli_process(char*data,int len,void*args)
{
#define BUFSIZE 40
	int ret = 0;
	char *out;
	char *ptr, *url = NULL, *method = NULL, *header = NULL, *body = NULL;
	int port = 5683;
	coap_session_t *s;
	coap_endpoint_t *ep;
	coap_address_t remote_addr;
	coap_pdu_t *pdu;
	method_t m = COAP_REQUEST_GET;
	coap_optlist_t *optlist = NULL;
	unsigned char portbuf[2];
	unsigned char _buf[BUFSIZE];
	unsigned char *buf = _buf;
	size_t buflen;
	int res;
	char cliresp[128] = "200 ok!\n";

	cJSON *json=cJSON_Parse(data);
	if(!json)
	{
		printf("text is not json format!\n");return -1;
	}
	out=cJSON_Print(json);
	printf("%s\n",out);
	free(out);

	cJSON_GetStringByKey(json, "method", method);
	cJSON_GetStringByKey(json, "url", url);
	//cJSON_GetStringByKey(json, "header", header);
	cJSON_GetStringByKey(json, "body", body);

	if(!method || !url)
	{
		ret = -1;
		goto end;
	}
	if(!strcasecmp(method, "get"))
	{
		m = COAP_REQUEST_GET;
	}else if(!strcasecmp(method, "post"))
	{
		m = COAP_REQUEST_POST;
	}else if(!strcasecmp(method, "put"))
	{
		m = COAP_REQUEST_PUT;
	}else if(!strcasecmp(method, "delete"))
	{
		m = COAP_REQUEST_DELETE;
	}

	ptr = url;
	if((ptr = strchr(url, '?')) && strlen(ptr+1))
	{
		*ptr = '\0';
		buflen = BUFSIZE;
        buf = _buf;
        res = coap_split_query(ptr+1, strlen(ptr+1), buf, &buflen);
  
        while (res--) {
          coap_insert_optlist(&optlist,
                      coap_new_optlist(COAP_OPTION_URI_QUERY,
                      coap_opt_length(buf),
                      coap_opt_value(buf)));
  
          buf += coap_opt_size(buf);
        }
	}
	if((ptr = strchr(url, '/')) && strlen(ptr+1))
	{
		*ptr = '\0';
		buflen = BUFSIZE;
        res = coap_split_path(ptr+1, strlen(ptr+1), buf, &buflen);
  
        while (res--) {
          coap_insert_optlist(&optlist,
                      coap_new_optlist(COAP_OPTION_URI_PATH,
                      coap_opt_length(buf),
                      coap_opt_value(buf)));
  
          buf += coap_opt_size(buf);
        }
	}
	if((ptr = strchr(url, ':')) && strlen(ptr+1))
	{
		*ptr = '\0';
		port = atoi(ptr+1);
		coap_insert_optlist(&optlist,
                  coap_new_optlist(COAP_OPTION_URI_PORT,
                  coap_encode_var_safe(portbuf, sizeof(portbuf), port),
                  portbuf));
	}

	remote_addr.size = (socklen_t)sizeof(remote_addr.addr.sin);
	remote_addr.addr.sa.sa_family = AF_INET;
	remote_addr.addr.sin.sin_port = htons(port);
	remote_addr.addr.sin.sin_addr.s_addr = inet_addr(url);

	//printf("search session by size:%d, family:%d, port:%x, addr:%x\n", remote_addr.size, remote_addr.addr.sa.sa_family, 
	//  remote_addr.addr.sin.sin_port, remote_addr.addr.sin.sin_addr.s_addr);
	
	s = coap_session_get_by_peer(g_ctx, &remote_addr, 0);
	printf("find session %p\n", s);
	if(s)
	{
		unsigned char rand_token[8] = {0};
		int64_t randnum = 0;
		coap_string_t token = {.s = rand_token, .length = sizeof(rand_token)};
		randnum = (int64_t)rand();
		memcpy(rand_token, &randnum, sizeof(rand_token));
		pdu = coap_new_request(g_ctx, s, m, &optlist, body, body ? strlen(body) : 0, token);
		if(pdu)
		{
			//coap_show_pdu(pdu);
			coap_send(s, pdu);
		}
	}
end:
	conn_send(args, cliresp, strlen(cliresp));
	if(json)cJSON_Delete(json);
	if(method)free(method);
	if(url)free(url);
	//if(header)free(header);
	if(body)free(body);
	coap_delete_optlist(optlist);
	return ret;
}

int
main(int argc, char **argv) {
  coap_context_t  *ctx;
  coap_tick_t now;
  unsigned wait_ms;

  clock_offset = time(NULL);

  appame = argv[0];
  char *optionlong = "A:g:p:v:l:";
  if(!start_main(argc, argv, optionlong, NULL,
					extra_option,
					cli_process))
  	{
  		return 0;
  	}
  
  coap_startup();
  coap_dtls_set_log_level(log_level);
  coap_set_log_level(log_level);

  ctx = get_context(addr_str, port_str);
  if (!ctx)
    return -1;
  g_ctx = ctx;

  init_resources(ctx);

  /* join multicast group if requested at command line */
  if (group)
    coap_join_mcast_group(ctx, group);

  signal(SIGINT, handle_sigint);

  wait_ms = COAP_RESOURCE_CHECK_TIME * 1000;

  while ( !quit ) {
    int result = coap_run_once( ctx, wait_ms );
    if ( result < 0 ) {
      break;
    } else if ( (unsigned)result < wait_ms ) {
      wait_ms -= result;
    } else {
      if ( time_resource ) {
	coap_resource_notify_observers(time_resource, NULL);
      }
      wait_ms = COAP_RESOURCE_CHECK_TIME * 1000;
    }

#ifndef WITHOUT_ASYNC
    /* check if we have to send asynchronous responses */
    coap_ticks( &now );
    check_async(ctx, now);
#endif /* WITHOUT_ASYNC */

#ifndef WITHOUT_OBSERVE
    /* check if we have to send observe notifications */
    coap_check_notify(ctx);
#endif /* WITHOUT_OBSERVE */
  }

  coap_free_context(ctx);
  coap_cleanup();

  return 0;
}

