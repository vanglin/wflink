#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/wait.h>
#include "stddef.h"
#include <pthread.h>
#include <time.h>
#include <signal.h>
#include <poll.h>

#include "wflink.h"
#include "wflink_config.h"
#include "net_timer.h"
#include "coap_client.h"
#include "coap2/coap.h"

#ifdef __GNUC__
#define UNUSED_PARAM __attribute__ ((unused))
#else /* not a GCC */
#define UNUSED_PARAM
#endif /* GCC */

#define container_of(ptr, type, member)         \
        ((type *)( (char *)(ptr) - offsetof(type,member) ))

#define COAP_RESOURCE_CHECK_TIME 2

#define MAX_USER 128 /* Maximum length of a user name (i.e., PSK
                      * identity) in bytes. */
#define MAX_KEY   64 /* Maximum length of a key (i.e., PSK) in bytes. */

extern wflink_context_t g_wflink_ctx;
extern wflink_cfg_t g_wflink_cfg;

/* temporary storage for dynamic resource representations */
static int quit = 0;

char *group = NULL;

int flags = 0;

#define FLAGS_BLOCK 0x01

static coap_string_t output_file = { 0, NULL };   /* output file name */
static FILE *file = NULL;               /* output file stream */

static int reliable = 0;

/* CoAP message types
 *	CON       0
 *	NON       1
 *	ACK       2
 *	RST       3
 */
unsigned char msgtype = COAP_MESSAGE_CON; /* only used on UDP transport */

typedef unsigned char method_t;

/* Used for block transaction,
 * When data divided into several packages.
 * coap_transaction is identified by 'the_token'.
 */
typedef struct
{
	int ready;
	char *string_uri;
	coap_uri_t uri;
	method_t method;
	coap_string_t the_token;
	coap_optlist_t *optlist;
	coap_string_t payload;
	coap_block_t block;
	coap_string_t response;
	coap_session_t *session;
	int try_count;
	int noreply_max;	//disconnect_flag(1 << 17), relogin_flag(1 << 16), timeout_flag(0xffff)
	long timer_id;
}coap_transaction_t;

sig_mutex_t coap_trans_lock;
struct list_head coap_transactions;

unsigned int wait_seconds = 90;		/* default timeout in seconds */
unsigned int wait_ms = 0;
int wait_ms_reset = 0;
int obs_started = 0;
unsigned int obs_seconds = 30;          /* default observe time */
unsigned int obs_ms = 0;                /* timeout for current subscription */
int obs_ms_reset = 0;

int create_uri_opts = 1;

// 1. Local bind info
char bind_addr[NI_MAXHOST] = "192.168.10.1";
char bind_port[NI_MAXSERV] = "6684";
/*
 * COAP_PROTO_NONE	  0
 * COAP_PROTO_UDP	  1
 * COAP_PROTO_DTLS	  2
 * COAP_PROTO_TCP	  3
 * COAP_PROTO_TLS	  4
*/
int transport = COAP_PROTO_TLS;

// 2. Server/Proxy info
static coap_string_t coap_server_addr = { 12, "192.168.10.1" };
static uint16_t coap_server_port = COAPS_DEFAULT_PORT;
static coap_string_t proxy = { 0, NULL };
static uint16_t coap_proxy_port = COAP_DEFAULT_PORT;
static char coap_server_ip[INET6_ADDRSTRLEN] = {0};

coap_log_t log_level = LOG_DEBUG;
unsigned char psk_user[MAX_USER + 1] = "CoAP", psk_key[MAX_KEY] = "secretPSK";
ssize_t psk_user_length = 4, psk_key_length = 9;

static int cmdline_uri(coap_uri_t *uri, coap_optlist_t **optlist, char *arg, int create_uri_opts);

/**
 * Calculates decimal value from hexadecimal ASCII character given in
 * @p c. The caller must ensure that @p c actually represents a valid
 * heaxdecimal character, e.g. with isxdigit(3).
 *
 * @hideinitializer
 */
#define hexchar_to_dec(c) ((c) & 0x40 ? ((c) & 0x0F) + 9 : ((c) & 0x0F))

/**
 * Decodes percent-encoded characters while copying the string @p seg
 * of size @p length to @p buf. The caller of this function must
 * ensure that the percent-encodings are correct (i.e. the character
 * '%' is always followed by two hex digits. and that @p buf provides
 * sufficient space to hold the result. This function is supposed to
 * be called by make_decoded_option() only.
 *
 * @param seg     The segment to decode and copy.
 * @param length  Length of @p seg.
 * @param buf     The result buffer.
 */
static void
decode_segment(const unsigned char *seg, size_t length, unsigned char *buf) {

  while (length--) {

    if (*seg == '%') {
      *buf = (hexchar_to_dec(seg[1]) << 4) + hexchar_to_dec(seg[2]);

      seg += 2; length -= 2;
    } else {
      *buf = *seg;
    }

    ++buf; ++seg;
  }
}

/**
 * Runs through the given path (or query) segment and checks if
 * percent-encodings are correct. This function returns @c -1 on error
 * or the length of @p s when decoded.
 */
static int
check_segment(const unsigned char *s, size_t length) {

  size_t n = 0;

  while (length) {
    if (*s == '%') {
      if (length < 2 || !(isxdigit(s[1]) && isxdigit(s[2])))
        return -1;

      s += 2;
      length -= 2;
    }

    ++s; ++n; --length;
  }

  return n;
}

static int
cmdline_input(char *text, coap_string_t *buf) {
  int len;
  len = check_segment((unsigned char *)text, strlen(text));

  if (len < 0)
    return 0;

  buf->s = (unsigned char *)coap_malloc(len);
  if (!buf->s)
    return 0;

  buf->length = len;
  decode_segment((unsigned char *)text, strlen(text), buf->s);
  return 1;
}

#define METHOD_MAP_FROM_COMMON_TO_INTERNAL 0
#define METHOD_MAP_FROM_INTERNAL_TO_COMMON 1

/* direction: 0 from common to internal
 * direction: 1 from internal to common
 */
static int method_mmap(int direction, method_type_e *method, method_t *coap_method)
{
	int ret = 0;
	if(METHOD_MAP_FROM_COMMON_TO_INTERNAL == direction)
	{
		switch(*method)
		{
			case REQUEST_METHOD_GET:
				*coap_method = COAP_REQUEST_GET;
				break;
			case REQUEST_METHOD_POST:
				*coap_method = COAP_REQUEST_POST;
				break;
			case REQUEST_METHOD_PUT:
				*coap_method = COAP_REQUEST_PUT;
				break;
			case REQUEST_METHOD_DELETE:
				*coap_method = COAP_REQUEST_DELETE;
				break;
			default:
				ret = -1;
				break;
		}
	}
	else
	{
		switch(*coap_method)
		{
			case COAP_REQUEST_GET:
				*method = REQUEST_METHOD_GET;
				break;
			case COAP_REQUEST_POST:
				*method = REQUEST_METHOD_POST;
				break;
			case COAP_REQUEST_PUT:
				*method = REQUEST_METHOD_PUT;
				break;
			case COAP_REQUEST_DELETE:
				*method = REQUEST_METHOD_DELETE;
				break;
			default:
				ret = -1;
				break;
		}
	}
	return ret;
}

static void free_transaction(coap_transaction_t *trans)
{
	if(trans)
	{
		if(-1 != trans->timer_id)timer_del(g_wflink_ctx.htimer, trans->timer_id);
		if(trans->string_uri)free(trans->string_uri);
		if(trans->the_token.s)free(trans->the_token.s);
		if(trans->payload.s)free(trans->payload.s);
		if(trans->response.s)free(trans->response.s);
		coap_delete_optlist(trans->optlist);
		free(container_of(trans, struct list_head, data));
	}
}

static coap_transaction_t *create_transaction(char *uri, method_type_e method, char *text)
{
	coap_transaction_t *trans = NULL;
	unsigned char rand_token[8] = {0};
	int64_t randnum = 0;
	int entry_size = sizeof(struct list_head) + sizeof(coap_transaction_t);
	struct list_head *entry = (struct list_head *)malloc(entry_size);
	if(entry)
	{
		trans = (coap_transaction_t *)entry->data;
		memset(entry, 0, entry_size);
		INIT_LIST_HEAD(entry);
		trans->string_uri = strdup(uri);
		if(method_mmap(METHOD_MAP_FROM_COMMON_TO_INTERNAL, &method, &trans->method) < 0)
		{
			goto end;
		}
		if(cmdline_uri(&trans->uri, &trans->optlist, trans->string_uri, create_uri_opts) < 0)
		{
			goto end;
		}
		randnum = (int64_t)rand();
		memcpy(rand_token, &randnum, sizeof(rand_token));
		trans->the_token.s = strdup(rand_token);
		trans->the_token.length = strlen(rand_token);
		if(!cmdline_input(text, &trans->payload))
		{
			trans->payload.length = 0;
		}
		trans->block.szx = 6;//{ .num = 0, .m = 0, .szx = 6 }
	}
	return trans;
end:
	free_transaction(trans);
	return NULL;
}

static void push_transaction(coap_transaction_t *trans)
{
	sig_mutex_lock(&coap_trans_lock);
	list_add_tail(container_of(trans, struct list_head, data), &coap_transactions);
	sig_mutex_unlock(&coap_trans_lock);
}

static void pop_transaction(coap_transaction_t *trans)
{
	sig_mutex_lock(&coap_trans_lock);
	list_del(container_of(trans, struct list_head, data));
	sig_mutex_unlock(&coap_trans_lock);
}

struct string2enum_t
{
	char *str;
	int type;
	
};

struct string2enum_t g_transport_names[] =
{
	{"udp", COAP_PROTO_UDP},
	{"tcp", COAP_PROTO_TCP},
	{"tls", COAP_PROTO_TLS},
	{"dtls", COAP_PROTO_DTLS},
};

int transport_mmap(char *key)
{
	int i = 0;
	if(key)
	{
		for(i = 0; i < sizeof(g_transport_names)/sizeof(g_transport_names[0]); i++)
		{
			if(!strncasecmp(key, g_transport_names[i].str, strlen(key)))
			{
				return g_transport_names[i].type;
			}
		}
	}
	return -1;
}

int coap_set_code(void *msg, int code)
{
	coap_pdu_t *resp = (coap_pdu_t *)msg;
	resp->code = COAP_RESPONSE_CODE(code);
	return 0;
}

/* If option value is number, use below API to transform
 * unsigned int coap_decode_var_bytes(const uint8_t *buf, unsigned int len);
 * args:
 *        buf - encoded bytes
 *        val - the count of the bytes
 * return:
 *        the number value(0~2^32)
 * note:
 *        N/A
 */
int coap_get_header(void *msg, char *key, char **value)
{
	// value received should be decoded according to the key type outside
	coap_opt_t *option = NULL;
	coap_opt_iterator_t opt_iter;
	coap_pdu_t *pdu = (coap_pdu_t *)msg;
	const uint8_t *val = NULL;
	uint16_t length = 0;
	option = coap_check_option(pdu, *(uint16_t *)key, &opt_iter);
	if(option)
	{		
		val = coap_opt_value(option);
		length = coap_opt_length(option);
		if(*value) *value = (char *)val;
		return length;
	}
	return -1;
}

/* If option value is number, use below API to transform
 * unsigned int coap_encode_var_bytes(uint8_t *buf, unsigned int val);
 * args:
 *        buf - container to receive the bytes
 *        val - the number value(0~2^32)
 * return:
 *        the count of the bytes
 * note:
 *        the size of buf must be 4B and inited with 0
 */
int coap_set_header(void *msg, char *key, char *value)
{
	// the value must be encoded into string format according to the key type outside. For more details, please see coap/pdu.h
	coap_pdu_t *pdu = (coap_pdu_t *)msg;
	int ret = 0;

	/* default encode with plain-text format */
	ret = coap_add_option(pdu, *(uint16_t *)key, strlen(value), value);
    return !ret;
}
int coap_get_body(void *msg, char **value, int *len)
{
	coap_pdu_t *pdu = (coap_pdu_t *)msg;
	int ret = 0;
	/* coap_get_data return 1 is success, 0 is failed */
	ret = coap_get_data(pdu, (size_t *)len, (uint8_t **)value);
	return !ret;
}
int coap_set_body(void *msg, char *value, int len)
{
	coap_pdu_t *pdu = (coap_pdu_t *)msg;
	int ret = 0;
	/* coap_add_data return 1 is success, 0 is failed */
	ret = coap_add_data(pdu, len, (unsigned char *)value);
	return !ret;
}

virtual_construct_t g_coap_constructor =
{
	.type = VCONS_COAP,
	.set_code = coap_set_code,
	.get_header = coap_get_header,
	.set_header = coap_set_header,
	.get_body = coap_get_body,
	.set_body = coap_set_body
};

/*****************************************
 *           resources start
 *****************************************/
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
sys_gateway_profile_callback(coap_context_t *ctx UNUSED_PARAM,
			  struct coap_resource_t *resource UNUSED_PARAM,
			  coap_session_t *session UNUSED_PARAM,
			  coap_pdu_t *request,
			  coap_binary_t *token UNUSED_PARAM,
			  coap_string_t *query UNUSED_PARAM,
			  coap_pdu_t *response) {
	method_type_e method;
	method_mmap(METHOD_MAP_FROM_INTERNAL_TO_COMMON, &method, &request->code);
	do_process_by_route((char *)resource->uri_path->s, method, &g_coap_constructor, (void *)request, (void *)response);
}

static int regiter_callback(void *processor, void *args)
{
	
	method_t coap_method;
	coap_context_t *ctx = (coap_context_t *)args;
	char *route = get_processor_property_route(processor, 0);
	msg_process *process = get_processor_property_process(processor, 0);
	coap_resource_t *r = coap_resource_init(coap_make_str_const(route), 0);
	int i = 0;
	for(i = 0; i < REQUEST_METHOD_MAX; i++)
	{
		if(process[i])
		{
			method_mmap(METHOD_MAP_FROM_COMMON_TO_INTERNAL, (method_type_e *)&i, &coap_method);
			coap_register_handler(r, coap_method, sys_gateway_profile_callback);
		}
	}
	coap_add_resource(ctx, r);
	return 0;
}

static void
init_resources(coap_context_t *ctx) {
  coap_resource_t *r;

  r = coap_resource_init(NULL, 0);
  coap_register_handler(r, COAP_REQUEST_GET, hnd_get_index);

  coap_add_attr(r, coap_make_str_const("ct"), coap_make_str_const("0"), 0);
  coap_add_attr(r, coap_make_str_const("title"), coap_make_str_const("\"General Info\""), 0);
  coap_add_resource(ctx, r);

  iterate_processors(NULL, regiter_callback, (void *)ctx);
}

/*****************************************
 *           resources end
 *****************************************/

static coap_session_t *
get_session(
  coap_context_t *ctx,
  const char *local_addr,
  const char *local_port,
  coap_proto_t proto,
  coap_address_t *dst,
  const char *identity,
  const uint8_t *key,
  unsigned key_len
) {
  coap_session_t *session = NULL;

  if ( local_addr ) {
    int s;
    struct addrinfo hints;
    struct addrinfo *result = NULL, *rp;

    memset( &hints, 0, sizeof( struct addrinfo ) );
    hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
    hints.ai_socktype = COAP_PROTO_RELIABLE(proto) ? SOCK_STREAM : SOCK_DGRAM; /* Coap uses UDP */
    hints.ai_flags = AI_PASSIVE | AI_NUMERICHOST | AI_NUMERICSERV | AI_ALL;

    s = getaddrinfo( local_addr, local_port, &hints, &result );
    if ( s != 0 ) {
      fprintf( stderr, "getaddrinfo: %s\n", gai_strerror( s ) );
      return NULL;
    }

    /* iterate through results until success */
    for ( rp = result; rp != NULL; rp = rp->ai_next ) {
      coap_address_t bind_addr;
      if ( rp->ai_addrlen <= sizeof( bind_addr.addr ) ) {
	coap_address_init( &bind_addr );
	bind_addr.size = rp->ai_addrlen;
	memcpy( &bind_addr.addr, rp->ai_addr, rp->ai_addrlen );
	if ( identity && key && (proto == COAP_PROTO_DTLS || proto == COAP_PROTO_TLS) )
	  session = coap_new_client_session_psk( ctx, &bind_addr, dst, proto, identity, key, key_len );
	else
	  session = coap_new_client_session( ctx, &bind_addr, dst, proto );
	if ( session )
	  break;
      }
    }
    freeaddrinfo( result );
  } else {
    if ( identity && key && (proto == COAP_PROTO_DTLS || proto == COAP_PROTO_TLS) )
      session = coap_new_client_session_psk( ctx, NULL, dst, proto, identity, key, key_len );
    else
      session = coap_new_client_session( ctx, NULL, dst, proto );
  }
  return session;
}


static inline int
check_token(coap_pdu_t *received, coap_pdu_t *sent) {
  return received->token_length == sent->token_length &&
    memcmp(received->token, sent->token, received->token_length) == 0;
}

coap_transaction_t *find_trans_by_condition(coap_pdu_t *received)
{
	coap_transaction_t *iter = NULL, *ret = NULL;
	struct list_head *pos, *n;
	if(!received)
	{
		return NULL;
	}
	sig_mutex_lock(&coap_trans_lock);
	list_for_each_safe(pos, n, &coap_transactions)
	{
		iter = (coap_transaction_t *)pos->data;
		if(received->token_length == iter->the_token.length &&
    		memcmp(received->token, iter->the_token.s, received->token_length) == 0)
		{
			ret = iter;
			break;
		}
	}
	sig_mutex_unlock(&coap_trans_lock);
	return ret;
}

static int
event_handler(coap_context_t *ctx UNUSED_PARAM,
              coap_event_t event,
              struct coap_session_t *session UNUSED_PARAM) {

  switch(event) {
  case COAP_EVENT_SESSION_CONNECTED:
  	sig_cond_signal(&g_wflink_ctx.coapClient.cond);
  	break;
  case COAP_EVENT_DTLS_CLOSED:
  case COAP_EVENT_TCP_CLOSED:
  case COAP_EVENT_SESSION_CLOSED:
    quit = 1;
    break;
  default:
    break;
  }
  return 0;
}

int collect_payload(coap_transaction_t *trans, const unsigned char *data, size_t len)
{
	if(trans)
	{
		int ori_len = trans->response.length;
		trans->response.length = trans->response.length + len;
		trans->response.s = realloc(trans->response.s, trans->response.length);
		assert(trans->response.s);
		memcpy(trans->response.s+ori_len, data, len);
		return trans->response.length;
	}
	return 0;
}

/* Upper layer APP handle
 * Arg - trans must be released after done
 */
int handle_payload(coap_transaction_t *trans, void *args)
{
	int ret = 0;
	pop_transaction(trans);
	//First delete transactino timer because of the time cost by process
	if(-1 != trans->timer_id)
	{
		timer_del(g_wflink_ctx.htimer, trans->timer_id);
		trans->timer_id = -1;
	}
	if(g_wflink_ctx.threadPool)
		add_task_pool(g_wflink_ctx.threadPool, trans->response.s, trans->response.length, args, platform_services_process);
	else
		platform_services_process(trans->response.s, trans->response.length, args);
	free_transaction(trans);
	return ret;
}

static coap_pdu_t *
coap_new_request(coap_context_t *ctx,
                 coap_session_t *session,
                 coap_transaction_t *trans) {
  coap_pdu_t *pdu;
  method_t m = trans->method;
  coap_optlist_t **options = &trans->optlist;
  unsigned char *data = trans->payload.s;
  size_t length = trans->payload.length;
  coap_string_t the_token = trans->the_token;
  coap_block_t block = trans->block;
  (void)ctx;

  if (!(pdu = coap_new_pdu(session)))
    return NULL;

  pdu->type = msgtype;
  pdu->tid = coap_new_message_id(session);
  pdu->code = m;

  pdu->token_length = (uint8_t)the_token.length;
  if ( !coap_add_token(pdu, the_token.length, the_token.s)) {
    coap_log(LOG_DEBUG,"cannot add token to request\n");
  }

  coap_add_optlist_pdu(pdu, options);

  if (length) {
    if ((flags & FLAGS_BLOCK) == 0)
      coap_add_data(pdu, length, data);
    else
      coap_add_block(pdu, length, data, block.num, block.szx);
  }

  if(!trans->session) trans->session = session;
  return pdu;
}

static void
message_handler(struct coap_context_t *ctx,
                coap_session_t *session,
                coap_pdu_t *sent,
                coap_pdu_t *received,
                const coap_tid_t id UNUSED_PARAM) {

  coap_pdu_t *pdu = NULL;
  coap_opt_t *block_opt;
  coap_opt_iterator_t opt_iter;
  unsigned char buf[4];
  coap_optlist_t *option;
  size_t len;
  unsigned char *databuf;
  coap_tid_t tid;
  coap_transaction_t *trans = NULL;
  coap_transaction_t emtpy_trans;
  coap_optlist_t *optlist = NULL;
  coap_block_t *block = NULL;
  coap_string_t *payload = NULL;
  memset(&emtpy_trans, 0, sizeof(emtpy_trans));

#if 0
  if (LOG_INFO <= coap_get_log_level()) {
    coap_log(LOG_DEBUG, "** process incoming %d.%02d response:\n",
          (received->code >> 5), received->code & 0x1F);
    coap_show_pdu(LOG_DEBUG,received);
  }
#endif

  if (received->type == COAP_MESSAGE_RST) {
      coap_log(LOG_DEBUG, "got RST\n");
    return;
  }
  /* Only when CON && (UDP || DTLS), sent != NULL */
  if(COAP_PROTO_NOT_RELIABLE(session->proto) && msgtype == COAP_MESSAGE_CON) {
    if (!check_token(received, sent)) {
	  /* drop if this was just some message, or send RST in case of notification */
	  if (!sent && (received->type == COAP_MESSAGE_CON ||
					received->type == COAP_MESSAGE_NON))
		coap_send_rst(session, received);
	  return;
	}
  } else {
    trans = find_trans_by_condition(received);
	if(!trans)
	{
		coap_log(LOG_DEBUG, "match token failed\n");
		return;
	}
	else
	{
		emtpy_trans.method = trans->method;
		emtpy_trans.the_token = trans->the_token;
		emtpy_trans.block = trans->block;
		optlist = trans->optlist;
		block = &trans->block;
		payload = &trans->payload;
	}
  }

  /* output the received data, if any */
  if (COAP_RESPONSE_CLASS(received->code) == 2) {

    /* set obs timer if we have successfully subscribed a resource */
    if (!obs_started && coap_check_option(received, COAP_OPTION_SUBSCRIPTION, &opt_iter)) {
      coap_log(LOG_DEBUG, "observation relationship established, set timeout to %d\n", obs_seconds);
      //obs_started = 1;
      //obs_ms = obs_seconds * 1000;
      //obs_ms_reset = 1;
    }

    /* Got some data, check if block option is set. Behavior is undefined if
     * both, Block1 and Block2 are present. */
    block_opt = coap_check_option(received, COAP_OPTION_BLOCK2, &opt_iter);
    if (block_opt) { /* handle Block2 */
      uint16_t blktype = opt_iter.type;

      /* TODO: check if we are looking at the correct block number */
      if (coap_get_data(received, &len, &databuf)) {
	  	//append_to_output(databuf, len);
	  	collect_payload(trans, databuf, len);
      }

      if(COAP_OPT_BLOCK_MORE(block_opt)) {
        /* more bit is set */
        coap_log(LOG_DEBUG, "found the M bit, block size is %u, block nr. %u\n",
              COAP_OPT_BLOCK_SZX(block_opt),
              coap_opt_block_num(block_opt));

        /* create pdu with request for next block */
        pdu = coap_new_request(ctx, session, &emtpy_trans); /* first, create bare PDU w/o any option  */
        if ( pdu ) {
          /* add URI components from optlist */
          for (option = optlist; option; option = option->next ) {
            switch (option->number) {
              case COAP_OPTION_URI_HOST :
              case COAP_OPTION_URI_PORT :
              case COAP_OPTION_URI_PATH :
              case COAP_OPTION_URI_QUERY :
                coap_add_option(pdu, option->number, option->length,
                                option->data);
                break;
              default:
                ;     /* skip other options */
            }
          }

          /* finally add updated block option from response, clear M bit */
          /* blocknr = (blocknr & 0xfffffff7) + 0x10; */
          coap_log(LOG_DEBUG, "query block %d\n", (coap_opt_block_num(block_opt) + 1));
          coap_add_option(pdu,
                          blktype,
                          coap_encode_var_safe(buf, sizeof(buf), 
                                 ((coap_opt_block_num(block_opt) + 1) << 4) |
                                  COAP_OPT_BLOCK_SZX(block_opt)), buf);

          tid = coap_send(session, pdu);

          if (tid == COAP_INVALID_TID) {
            coap_log(LOG_DEBUG, "message_handler: error sending new request");
          } else {
	    //wait_ms = wait_seconds * 1000;
	    //wait_ms_reset = 1;
          }

          return;
        }
      }
    } else { /* no Block2 option */
      block_opt = coap_check_option(received, COAP_OPTION_BLOCK1, &opt_iter);

      if (block_opt) { /* handle Block1 */
        unsigned int szx = COAP_OPT_BLOCK_SZX(block_opt);
        unsigned int num = coap_opt_block_num(block_opt);
        coap_log(LOG_DEBUG, "found Block1 option, block size is %u, block nr. %u\n", szx, num);
        if (szx != block->szx) {
          unsigned int bytes_sent = ((block->num + 1) << (block->szx + 4));
          if (bytes_sent % (1 << (szx + 4)) == 0) {
            /* Recompute the block number of the previous packet given the new block size */
            block->num = (bytes_sent >> (szx + 4)) - 1;
            block->szx = szx;
            coap_log(LOG_DEBUG, "new Block1 size is %u, block number %u completed\n", (1 << (block->szx + 4)), block->num);
          } else {
            coap_log(LOG_DEBUG, "ignoring request to increase Block1 size, "
            "next block is not aligned on requested block size boundary. "
            "(%u x %u mod %u = %u != 0)\n",
                  block->num + 1, (1 << (block->szx + 4)), (1 << (szx + 4)),
                  bytes_sent % (1 << (szx + 4)));
          }
        }

        if (payload->length <= (block->num+1) * (1 << (block->szx + 4))) {
          coap_log(LOG_DEBUG, "upload ready\n");
          trans->ready = 1;
          goto end;
        }

        /* create pdu with request for next block */
        pdu = coap_new_request(ctx, session, &emtpy_trans); /* first, create bare PDU w/o any option  */
        if (pdu) {

          /* add URI components from optlist */
          for (option = optlist; option; option = option->next ) {
            switch (option->number) {
              case COAP_OPTION_URI_HOST :
              case COAP_OPTION_URI_PORT :
              case COAP_OPTION_URI_PATH :
              case COAP_OPTION_CONTENT_FORMAT :
              case COAP_OPTION_URI_QUERY :
                coap_add_option(pdu, option->number, option->length,
                                option->data);
                break;
              default:
              ;     /* skip other options */
            }
          }

          /* finally add updated block option from response, clear M bit */
          /* blocknr = (blocknr & 0xfffffff7) + 0x10; */
          block->num++;
          block->m = ((block->num+1) * (1 << (block->szx + 4)) < payload->length);

          coap_log(LOG_DEBUG, "send block %d\n", block->num);
          coap_add_option(pdu,
                          COAP_OPTION_BLOCK1,
                          coap_encode_var_safe(buf, sizeof(buf), 
                          (block->num << 4) | (block->m << 3) | block->szx), buf);

          coap_add_block(pdu,
                         payload->length,
                         payload->s,
                         block->num,
                         block->szx);
          coap_show_pdu(LOG_DEBUG,pdu);

	  tid = coap_send(session, pdu);

          if (tid == COAP_INVALID_TID) {
            coap_log(LOG_DEBUG, "message_handler: error sending new request");
          } else {
	    //wait_ms = wait_seconds * 1000;
	    //wait_ms_reset = 1;
          }

          return;
        }
      } else {
        /* There is no block option set, just read the data and we are done. */
        if (coap_get_data(received, &len, &databuf)) {
        	//append_to_output(databuf, len);
        	collect_payload(trans, databuf, len);
        }
      }
    }
  } else {      /* no 2.05 */

    /* check if an error was signaled and output payload if so */
    if (COAP_RESPONSE_CLASS(received->code) >= 4) {
      fprintf(stderr, "%d.%02d",
              (received->code >> 5), received->code & 0x1F);
      if (coap_get_data(received, &len, &databuf)) {
        collect_payload(trans, databuf, len);
        fprintf(stderr, " ");
        while(len--)
        fprintf(stderr, "%c", *databuf++);
      }
      fprintf(stderr, "\n");
    }

  }

  /* any pdu that has been created in this function must be sent by now */
  assert(pdu == NULL);

  /* our job is done, we can exit at any time */
  trans->ready = coap_check_option(received, COAP_OPTION_SUBSCRIPTION, &opt_iter) == NULL;
end:
  if(trans->ready)
	{
		handle_payload(trans, (void *)session);
	}
}

static int
resolve_address(const coap_string_t *server, struct sockaddr *dst) {

  struct addrinfo *res, *ainfo;
  struct addrinfo hints;
  static char addrstr[256];
  int error, len=-1;

  memset(addrstr, 0, sizeof(addrstr));
  if (server->length)
    memcpy(addrstr, server->s, server->length);
  else
    memcpy(addrstr, "localhost", 9);

  memset ((char *)&hints, 0, sizeof(hints));
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_family = AF_UNSPEC;

  error = getaddrinfo(addrstr, NULL, &hints, &res);

  if (error != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(error));
    return error;
  }

  for (ainfo = res; ainfo != NULL; ainfo = ainfo->ai_next) {
    switch (ainfo->ai_family) {
    case AF_INET6:
    case AF_INET:
      len = ainfo->ai_addrlen;
      memcpy(dst, ainfo->ai_addr, len);
      goto finish;
    default:
      ;
    }
  }

 finish:
  freeaddrinfo(res);
  return len;
}

void *start_coap_client(void *args)
{
	coap_context_t  *ctx = NULL;
	coap_endpoint_t *endpoint = NULL;
	coap_session_t *session = NULL;
	coap_address_t dst;
	void *addrptr = NULL;
	int result = -1;
	coap_pdu_t  *pdu;
	static coap_string_t server;
	uint16_t port = COAP_DEFAULT_PORT;
	char port_str[NI_MAXSERV] = "0";
	int res;
	//coap_tick_t now;
	coap_client_t *coapClient = (coap_client_t *)args;
	
	coap_startup();
	coap_dtls_set_log_level(log_level);
	coap_set_log_level(log_level);

	if(proxy.length) {
		server = proxy;
		port = coap_proxy_port;
	} else {
	    server = coap_server_addr;
	    port = coap_server_port;
	}

	/* resolve destination address where server should be sent */
	res = resolve_address(&server, &dst.addr.sa);

	if (res < 0) {
	  fprintf(stderr, "failed to resolve address\n");
	  exit(-1);
	}

	ctx = coap_new_context( NULL );
	if ( !ctx ) {
	  coap_log( LOG_EMERG, "cannot create context\n" );
	  goto finish;
	}
	init_resources(ctx);

  	dst.size = res;
	dst.addr.sin.sin_port = htons( port );
  
	session = get_session(
	  ctx,
	  bind_addr[0] ? bind_addr : NULL, bind_port,
	  transport,
	  &dst,
	  psk_user_length > 0 ? (const char *)psk_user : NULL,
	  psk_key_length > 0  ? psk_key : NULL, (unsigned)psk_key_length
	);
  
	if ( !session ) {
	  coap_log( LOG_EMERG, "cannot create client session\n" );
	  goto finish;
	}
  
	/* add Uri-Host if server address differs from uri.host */
  
	switch (dst.addr.sa.sa_family) {
	case AF_INET:
	  addrptr = &dst.addr.sin.sin_addr;
	  /* create context for IPv4 */
	  break;
	case AF_INET6:
	  addrptr = &dst.addr.sin6.sin6_addr;
	  break;
	default:
	  ;
	}

  	if(addrptr)
	{
		inet_ntop(dst.addr.sa.sa_family, addrptr, coap_server_ip, sizeof(coap_server_ip));
	}
	coap_register_option(ctx, COAP_OPT_ACCESS_TOKEN_ID);
	coap_register_option(ctx, COAP_OPT_REQ_ID);
	coap_register_option(ctx, COAP_OPT_DEV_ID);
	coap_register_option(ctx, COAP_OPT_USER_ID);
	coap_register_option(ctx, COAP_OPTION_BLOCK2);
	coap_register_response_handler(ctx, message_handler);
	coap_register_event_handler(ctx, event_handler);
    
 	/* join multicast group if requested at command line */
  if (group)
    coap_join_mcast_group(ctx, group);

  wait_ms = COAP_RESOURCE_CHECK_TIME * 1000;

  result = 0;
  sig_mutex_lock(&coapClient->lock);
  coapClient->session = (void *)session;
  coapClient->pid = pthread_self();
  quit = 0; // reset quit
  sig_mutex_unlock(&coapClient->lock);

  while ( !quit ) {
    int result = coap_run_once( ctx, wait_ms );
    if ( result < 0 ) {
      break;
    } else if ( (unsigned)result < wait_ms ) {
      wait_ms -= result;
    } else {
      //if ( time_resource ) {
	//coap_resource_set_dirty(time_resource, NULL);
      }
      wait_ms = COAP_RESOURCE_CHECK_TIME * 1000;
    }

finish:
#ifndef WITHOUT_ASYNC
    /* check if we have to send asynchronous responses */
    //coap_ticks( &now );
    //check_async(ctx, now);
#endif /* WITHOUT_ASYNC */

#ifndef WITHOUT_OBSERVE
    /* check if we have to send observe notifications */
    coap_check_notify(ctx);
#endif /* WITHOUT_OBSERVE */

  coap_session_release( session );
  coap_free_context(ctx);
  coap_cleanup();

  return NULL;
}

int stop_coap_client(void *args)
{
	coap_session_t *session = NULL;
	coap_context_t  *ctx = NULL;
	coap_client_t *coapClient = (coap_client_t *)args;

	sig_mutex_lock(&coapClient->lock);
	quit = 1;
	coapClient->session = NULL;
	coapClient->pid = -1;
	sig_mutex_unlock(&coapClient->lock);
	
	return 0;
}

/* Called after processing the options from the commandline to set
 * Block1 or Block2 depending on method. */
static void
set_blocksize(method_t method, coap_string_t *payload, coap_optlist_t *optlist, coap_block_t *block) {
  static unsigned char buf[4];	/* hack: temporarily take encoded bytes */
  uint16_t opt;
  unsigned int opt_length;

  if (method != COAP_REQUEST_DELETE) {
    opt = method == COAP_REQUEST_GET ? COAP_OPTION_BLOCK2 : COAP_OPTION_BLOCK1;

    block->m = (opt == COAP_OPTION_BLOCK1) &&
      ((1u << (block->szx + 4)) < payload->length);

    opt_length = coap_encode_var_safe(buf, sizeof(buf), 
          (block->num << 4 | block->m << 3 | block->szx));

    coap_insert_optlist(&optlist, coap_new_optlist(opt, opt_length, buf));
  }
}

#define ISEQUAL_CI(a,b) \
  ((a) == (b) || (islower(b) && ((a) == ((b) - 0x20))))

int
_coap_split_uri(const unsigned char *str_var, size_t len, coap_uri_t *uri) {
  const unsigned char *p, *q;
  int res = 0;

  if (!str_var || !uri)
    return -1;

  memset(uri, 0, sizeof(coap_uri_t));
  uri->port = COAP_DEFAULT_PORT;

  /* search for scheme */
  p = str_var;
  if (*p == '/') {
    q = p;
    goto path;
  }

  q = (unsigned char *)COAP_DEFAULT_SCHEME;
  while (len && *q && ISEQUAL_CI(*p, *q)) {
    ++p; ++q; --len;
  }
  
  /* If q does not point to the string end marker '\0', the schema
   * identifier is wrong. */
  if (*q) {
    res = -1;
    goto error;
  }

  /* There might be an additional 's', indicating the secure version: */
  if (len && (*p == 's')) {
    ++p; --len;
    uri->scheme = COAP_URI_SCHEME_COAPS;
    uri->port = COAPS_DEFAULT_PORT;
  } else {
    uri->scheme = COAP_URI_SCHEME_COAP;
  }

  /* There might be and addition "+tcp", indicating reliable transport: */
  if (len>=4 && p[0] == '+' && p[1] == 't' && p[2] == 'c' && p[3] == 'p' ) {
    p += 4;
    len -= 4;
    if (uri->scheme == COAP_URI_SCHEME_COAPS)
      uri->scheme = COAP_URI_SCHEME_COAPS_TCP;
    else
      uri->scheme = COAP_URI_SCHEME_COAP_TCP;
  }
  q = (unsigned char *)"://";
  while (len && *q && *p == *q) {
    ++p; ++q; --len;
  }

  if (*q) {
    res = -2;
    goto error;
  }

  /* p points to beginning of Uri-Host */
  q = p;
  if (len && *p == '[') {	/* IPv6 address reference */
    ++p;
    
    while (len && *q != ']') {
      ++q; --len;
    }

    if (!len || *q != ']' || p == q) {
      res = -3;
      goto error;
    } 

    COAP_SET_STR(&uri->host, q - p, (unsigned char *)p);
    ++q; --len;
  } else {			/* IPv4 address or FQDN */
    while (len && *q != ':' && *q != '/' && *q != '?') {
      ++q;
      --len;
    }

    if (p == q) {
      res = -3;
      goto error;
    }

    COAP_SET_STR(&uri->host, q - p, (unsigned char *)p);
  }

  /* check for Uri-Port */
  if (len && *q == ':') {
    p = ++q;
    --len;
    
    while (len && isdigit(*q)) {
      ++q;
      --len;
    }

    if (p < q) {		/* explicit port number given */
      int uri_port = 0;
    
      while (p < q)
	      uri_port = uri_port * 10 + (*p++ - '0');

      /* check if port number is in allowed range */
      if (uri_port > 65535) {
	      res = -4;
	      goto error;
      }

      uri->port = (uint16_t)uri_port;
    } 
  }
  
 path:		 /* at this point, p must point to an absolute path */

  if (!len)
    goto end;
  
  if (*q == '/') {
    p = ++q;
    --len;

    while (len && *q != '?') {
      ++q;
      --len;
    }
  
    if (p < q) {
      COAP_SET_STR(&uri->path, q - p, (unsigned char *)p);
      p = q;
    }
  }

  /* Uri_Query */
  if (len && *p == '?') {
    ++p;
    --len;
    COAP_SET_STR(&uri->query, len, (unsigned char *)p);
    len = 0;
  }

  end:
  return len ? -1 : 0;
  
  error:
  return res;
}

static uint16_t
get_default_port(const coap_uri_t *u) {
  return coap_uri_scheme_is_secure(u) ? COAPS_DEFAULT_PORT : COAP_DEFAULT_PORT;
}

/**
 * Sets global URI options according to the URI passed as @p arg.
 * This function returns 0 on success or -1 on error.
 *
 * @param arg             The URI string.
 * @param create_uri_opts Flags that indicate whether Uri-Host and
 *                        Uri-Port should be suppressed.
 * @return 0 on success, -1 otherwise
 */
static int
cmdline_uri(coap_uri_t *uri, coap_optlist_t **optlist, char *arg, int create_uri_opts) {
  unsigned char portbuf[2];
#define BUFSIZE 40
  unsigned char _buf[BUFSIZE];
  unsigned char *buf = _buf;
  size_t buflen;
  int res;

  if (proxy.length) {   /* create Proxy-Uri from argument */
    size_t len = strlen(arg);
    while (len > 270) {
      coap_insert_optlist(optlist,
                  coap_new_optlist(COAP_OPTION_PROXY_URI,
                  270,
                  (unsigned char *)arg));

      len -= 270;
      arg += 270;
    }

    coap_insert_optlist(optlist,
                coap_new_optlist(COAP_OPTION_PROXY_URI,
                len,
                (unsigned char *)arg));

  } else {      /* split arg into Uri-* options */
    if (_coap_split_uri((unsigned char *)arg, strlen(arg), uri) < 0) {
      coap_log(LOG_ERR, "invalid CoAP URI\n");
      return -1;
    }

    if (uri->scheme==COAP_URI_SCHEME_COAPS && !reliable && !coap_dtls_is_supported()) {
      coap_log(LOG_EMERG, "coaps URI scheme not supported in this version of libcoap\n");
      return -1;
    }

    if ((uri->scheme==COAP_URI_SCHEME_COAPS_TCP || (uri->scheme==COAP_URI_SCHEME_COAPS && reliable)) && !coap_tls_is_supported()) {
      coap_log(LOG_EMERG, "coaps+tcp URI scheme not supported in this version of libcoap\n");
      return -1;
    }

    if (uri->port != get_default_port(uri) && create_uri_opts) {
      coap_insert_optlist(optlist,
                  coap_new_optlist(COAP_OPTION_URI_PORT,
                  coap_encode_var_safe(portbuf, sizeof(portbuf), uri->port),
                  portbuf));
    }

    if (uri->path.length) {
      buflen = BUFSIZE;
      res = coap_split_path(uri->path.s, uri->path.length, buf, &buflen);

      while (res--) {
        coap_insert_optlist(optlist,
                    coap_new_optlist(COAP_OPTION_URI_PATH,
                    coap_opt_length(buf),
                    coap_opt_value(buf)));

        buf += coap_opt_size(buf);
      }
    }

    if (uri->query.length) {
      buflen = BUFSIZE;
      buf = _buf;
      res = coap_split_query(uri->query.s, uri->query.length, buf, &buflen);

      while (res--) {
        coap_insert_optlist(optlist,
                    coap_new_optlist(COAP_OPTION_URI_QUERY,
                    coap_opt_length(buf),
                    coap_opt_value(buf)));

        buf += coap_opt_size(buf);
      }
    }
  }

  return 0;
}

void *create_coap_request_transaction(method_type_e method, char *uri_str, char *text, int noreply_max)
{
	coap_transaction_t *trans = NULL;
	trans = create_transaction(uri_str, method, text);
	if(trans)
	{
		/* construct CoAP message */
		if (!proxy.length
			&& (strlen(coap_server_ip) != trans->uri.host.length
			|| memcmp(coap_server_ip, trans->uri.host.s, trans->uri.host.length) != 0)
			&& create_uri_opts) {
			  /* add Uri-Host */
	  
			  coap_insert_optlist(&trans->optlist,
						  coap_new_optlist(COAP_OPTION_URI_HOST,
						  trans->uri.host.length,
						  trans->uri.host.s));
		}
		/* set block option if requested at commandline */
		if (flags & FLAGS_BLOCK)
		  set_blocksize(trans->method, &trans->payload, trans->optlist, &trans->block);

		/* set max retry */
		trans->noreply_max = noreply_max;
	}
	return (void *)trans;
}

static void retransmission(void *userdata)
{
	coap_transaction_t *trans = NULL;
	int ret = 0;
	if(userdata)
	{
		trans = (coap_transaction_t *)userdata;
		if(TIMEOUT_FLAG == (TIMEOUT_FLAG & trans->noreply_max) || trans->try_count < (TIMEOUT_FLAG & trans->noreply_max))
		{
			trans->try_count++;
			if(COAP_MESSAGE_NON == msgtype || COAP_PROTO_RELIABLE(trans->session->proto))
			{
				ret = send_coap_request((void *)trans->session, userdata);
				if(ret)
				{
					DBGPRINT(DEBUG_ERROR, "Resend coap request failed!!!\n");
				}
			}
		}
		else
		{
			trans->try_count = 0;
			pop_transaction(trans);
			free_transaction(trans);
			if(DISCONNECT_FLAG & trans->noreply_max)
			{
				stop_coap_client_and_reinit();
				if(RELOGIN_FLAG & trans->noreply_max)
				{
					start_relogin();
				}
			}
		}
	}
}

int send_coap_request(void *coap_client, void *vtrans)
{
	coap_session_t *session = (coap_session_t *)coap_client;
	coap_context_t  *ctx = session->context;
	coap_pdu_t  *pdu = NULL;
	int ret = 0;
	coap_transaction_t *trans = (coap_transaction_t *)vtrans;

	if(!trans)
	{
		goto finish;
	}
	
	if (! (pdu = coap_new_request(ctx, session, trans))) {
		ret = -1;
		goto finish;
	}
	
#if 0
	if (LOG_INFO <= coap_get_log_level()) {
		coap_log(LOG_EMERG, "sending CoAP request:\n");
		coap_show_pdu(LOG_DEBUG,pdu);
	}
#endif

	ret = coap_send(session, pdu);
	if(COAP_INVALID_TID == ret)
	{
		ret = -1;
		goto finish;
	}
	// need to add a time task see 'long timer_id' in coap_transaction_t
	// transaction must be released when timeout
	ret = 0;
	if(!trans->try_count)
	{
		push_transaction(trans);
		if(pdu->type == COAP_MESSAGE_CON && COAP_PROTO_NOT_RELIABLE(session->proto))
		{
			const coap_fixed_point_t ato = {COAP_RESPONSE_TIMEOUT_SEC, 0};
			coap_session_set_max_retransmit(trans->session, TIMEOUT_FLAG & trans->noreply_max);
			coap_session_set_ack_timeout(trans->session, ato);
		}
		trans->timer_id = timer_add(g_wflink_ctx.htimer, 0, COAP_RESPONSE_TIMEOUT_SEC * 1000, retransmission, (void *)trans);
	}

finish:
	if(-1 == ret)
	{
		free_transaction(trans);
	}
	return ret;
}

static void load_coap_config()
{
	int itmp;
	// 1. Local bind info
	if(g_wflink_cfg.coap.bind_client_address && strlen(g_wflink_cfg.coap.bind_client_address))
	{
		strncpy(bind_addr, g_wflink_cfg.coap.bind_client_address, sizeof(bind_addr));
	}
	if(g_wflink_cfg.coap.bind_client_port > 0 && g_wflink_cfg.coap.bind_client_port < 65536)
	{
		snprintf(bind_port, sizeof(bind_port), "%d", g_wflink_cfg.coap.bind_client_port);
	}

	// 2. Server/Proxy info
	if(g_wflink_cfg.coap.server_address && strlen(g_wflink_cfg.coap.server_address))
	{
		coap_server_addr.s = g_wflink_cfg.coap.server_address;
		coap_server_addr.length = strlen(g_wflink_cfg.coap.server_address);
	}
	if(g_wflink_cfg.coap.server_port > 0 && g_wflink_cfg.coap.server_port < 65536)
	{
		coap_server_port = g_wflink_cfg.coap.server_port;
	}
	if((itmp = transport_mmap(g_wflink_cfg.coap.transport)) > 0)
	{
		transport = itmp;
	}
	if(g_wflink_cfg.coap.proxy_address && strlen(g_wflink_cfg.coap.proxy_address))
	{
		proxy.s = g_wflink_cfg.coap.proxy_address;
		proxy.length = strlen(g_wflink_cfg.coap.proxy_address);
	}
	if(g_wflink_cfg.coap.proxy_server_port > 0 && g_wflink_cfg.coap.proxy_server_port < 65536)
	{
		coap_proxy_port = g_wflink_cfg.coap.proxy_server_port;
	}
	// 3. PSK
	if(g_wflink_cfg.coap.psk_user && strlen(g_wflink_cfg.coap.psk_user))
	{
		strncpy(psk_user, g_wflink_cfg.coap.psk_user, sizeof(psk_user));
	}
	if(g_wflink_cfg.coap.psk_key && strlen(g_wflink_cfg.coap.psk_key))
	{
		strncpy(psk_key, g_wflink_cfg.coap.psk_key, sizeof(psk_key));
	}
}

int init_coap_client(void)
{
	sig_mutex_init(&coap_trans_lock, NULL);
	INIT_LIST_HEAD(&coap_transactions);
	load_coap_config();
	return 0;
}

int get_coap_server_address(char *dst, int size)
{
	if(dst && size >= coap_server_addr.length)
	{
		strncpy(dst, coap_server_addr.s, coap_server_addr.length);
		return coap_server_addr.length;
	}
	return -1;
}

int get_coap_transport(void)
{
	return transport;
}

int set_options_access_token(void *vtrans, char *access_token)
{
	coap_transaction_t *trans = (coap_transaction_t *)vtrans;
	if(!trans)
		return -1;
	coap_insert_optlist(&trans->optlist,
	  coap_new_optlist(COAP_OPT_ACCESS_TOKEN_ID,
	  strlen(access_token),
	  access_token));
	return 0;
}
