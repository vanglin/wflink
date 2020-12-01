#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "wflink.h"
#include "libhttpd.h"

typedef struct
{
	char *buf;
	int size;
	int len;
}string_container;

char *httpd_err400form =
    "Your request has bad syntax or is inherently impossible to satisfy.\n";
static char* err501form =
    "The requested method '%.80s' is not implemented by this server.\n";

char *mime_header_format = "Content-Type: %s\r\nContent-Length: %d\r\n";
const char *default_mime_type = "text/html";
const char *json_mime_type = "application/json";

static void strdecode( char* to, char* from );
static void de_dotdot( char* file );

/* seperate buffer using '\r','\n','\r\n'
 * Return next line start point if it exists.
 */
static char *get_one_line(char *buf, int len)
{
	char *pos = NULL;
	char *next = NULL;
	if(pos = strchr(buf, '\r'))
	{
		*pos = '\0';
		if(pos < buf + len -1)
		{
			next = pos+1;
			if(*(++pos) == '\n')
			{
				*pos = '\0';
				if(pos < buf + len -1)
				{
					next = pos+1;
				}
				else
				{
					next = NULL;
				}
			}
		}
		else
		{
			next = NULL;
		}
	}
	else if(pos = strchr(buf, '\n'))
	{
		*pos = '\0';
		if(pos < buf + len -1)
		{
			next = pos+1;
		}
		else
		{
			next = NULL;
		}
	}
	return next;
}
static int set_response_error(wflink_msg_t*rmsg, int status, char *header, char *body, int len)
{
	rmsg->firstLine.res.status = status;
	rmsg->firstLine.res.detail = get_status_code_details(status);
	int hlen = strlen(header);
	char *buf = NULL;
	if(header&&hlen)
	{
		ami_line_parse(header, hlen, "\r\n", (char *)&rmsg->header);
	}
	if(body&&len)
	{
		rmsg->bodyPtr = body;
		rmsg->bodyLen = len;
		if(!header || !hlen)
		{
			buf = calloc(1, 256);//need to release by wflink_msg_internal_free()
			hlen = snprintf(buf, sizeof(buf), mime_header_format, default_mime_type, len);
			ami_line_parse(buf, hlen, "\r\n", (char *)&rmsg->header);
		}
	}
	return 0;
}
static int save_first_line(char *line,int len,wflink_msg_t*rx,wflink_msg_t*tx)
{
    char* method_str;
    char* url;
    char* protocol;
    char* reqhost;
    char* eol;
    char* cp;

	libhttpd_pvt *hc = (libhttpd_pvt *)rx->pvt;
	if(!hc)
		return -1;
	
	hc->mime_flag = 1;
	method_str = line;
	url = strpbrk( method_str, " \t\012\015" );
	if ( url == (char*) 0 )
	{
	set_response_error(tx, 400, "", httpd_err400form, strlen(httpd_err400form));
	return -1;
	}
	*url++ = '\0';
	url += strspn( url, " \t\012\015" );
	protocol = strpbrk( url, " \t\012\015" );
	if ( protocol == (char*) 0 )
	{
	protocol = "HTTP/0.9";
	hc->mime_flag = 0;
	}
	else
	{
	*protocol++ = '\0';
	protocol += strspn( protocol, " \t\012\015" );
	if ( *protocol != '\0' )
		{
		eol = strpbrk( protocol, " \t\012\015" );
		if ( eol != (char*) 0 )
		*eol = '\0';
		if ( strcasecmp( protocol, "HTTP/1.0" ) != 0 )
		hc->one_one = 1;
		}
	}
	rx->protocol = protocol;
	tx->protocol = strdup(protocol);

	/* Check for HTTP/1.1 absolute URL. */
	if ( strncasecmp( url, "http://", 7 ) == 0 )
	{
	if ( ! hc->one_one )
		{
		set_response_error(tx, 400, "", httpd_err400form, strlen(httpd_err400form));
		return -1;
		}
	reqhost = url + 7;
	url = strchr( reqhost, '/' );
	if ( url == (char*) 0 )
		{
		set_response_error(tx, 400, "", httpd_err400form, strlen(httpd_err400form));
		return -1;
		}
	*url = '\0';
	if ( strchr( reqhost, '/' ) != (char*) 0 || reqhost[0] == '.' )
		{
		set_response_error(tx, 400, "", httpd_err400form, strlen(httpd_err400form));
		return -1;
		}
	hc->reqhost = calloc(1, strlen(reqhost)+1);
	(void) strcpy( hc->reqhost, reqhost );
	*url = '/';
	}

	if ( *url != '/' )
	{
	set_response_error(tx, 400, "", httpd_err400form, strlen(httpd_err400form));
	return -1;
	}

	if ( strcasecmp( method_str, "GET" ) == 0 )
	rx->firstLine.req.method = REQUEST_METHOD_GET;
	else if ( strcasecmp( method_str, "POST" ) == 0 )
	rx->firstLine.req.method = REQUEST_METHOD_POST;
	else if ( strcasecmp( method_str, "PUT" ) == 0 )
	rx->firstLine.req.method = REQUEST_METHOD_PUT;
	else if ( strcasecmp( method_str, "DELETE" ) == 0 )
	rx->firstLine.req.method = REQUEST_METHOD_DELETE;
	else
	{
	set_response_error(tx, 501, "", err501form, strlen(err501form));
	return -1;
	}

	rx->firstLine.req.route = url;
	hc->encodedurl = calloc(1, strlen(url)+1);
	hc->decodedurl = calloc(1, strlen(url)+1);
	(void) strcpy( hc->encodedurl, url );
    strdecode( hc->decodedurl, hc->encodedurl );

	hc->origfilename = calloc(1, strlen(url)+1);
    (void) strcpy( hc->origfilename, &hc->decodedurl[1] );
    /* Special case for top-level URL. */
    if ( hc->origfilename[0] == '\0' )
	(void) strcpy( hc->origfilename, "." );

    /* Extract query string from encoded URL. */
    cp = strchr( hc->encodedurl, '?' );
    if ( cp != (char*) 0 )
	{
	++cp;
	hc->query = calloc(1, strlen(cp)+1);
	(void) strcpy( hc->query, cp );
	/* Remove query from (decoded) origfilename. */
	cp = strchr( hc->origfilename, '?' );
	if ( cp != (char*) 0 )
	    *cp = '\0';
	}

    de_dotdot( hc->origfilename );
    if ( hc->origfilename[0] == '/' ||
	 ( hc->origfilename[0] == '.' && hc->origfilename[1] == '.' &&
	   ( hc->origfilename[2] == '\0' || hc->origfilename[2] == '/' ) ) )
	{
	set_response_error(tx, 400, "", httpd_err400form, strlen(httpd_err400form));
	return -1;
	}
	return 0;
}
static int save_header(char *line, wflink_msg_t *msg)
{
	libhttpd_pvt *hc = (libhttpd_pvt *)msg->pvt;
	if(hc&&!hc->mime_flag)
	{
		/* HTTP/0.9 when protocol is null */
		return 0;
	}
	return save_line(line,(char*)&msg->header);
}
static int save_body(char *line, int len, wflink_msg_t *msg)
{
	msg->bodyPtr = line;
	msg->bodyLen = len;
	return 0;
}
int httpd_parse_request(char*buf,int len,wflink_msg_t*rx,wflink_msg_t*tx)
{
	int left=0;
	char *tmp=buf;
	char *pos=NULL;
	int count=0;
	int ret = -1;
	while(tmp&&(pos=get_one_line(tmp,len)))
	{
		if(!count)
		{
			ret = save_first_line(tmp,strlen(tmp),rx,tx);
			if(ret)
				return ret;
		}
		else
		{
			ret = save_header(tmp,rx);
			if(ret)
				return ret;
		}
		count++;
		if ('\0' == *tmp)
		{
			break;
		}
		tmp = pos;
	}
	if(pos)
	{
		count++;
		ret = save_body(pos,len-(pos-buf+1),rx);
	}
	return ret;
}

void httpd_pvt_internal_free(void *pvt)
{
	libhttpd_pvt *p = (libhttpd_pvt *)pvt;
	if(p)
	{
		WF_FREE(p->encodedurl);
		WF_FREE(p->reqhost);
		WF_FREE(p->decodedurl);
		WF_FREE(p->origfilename);
		WF_FREE(p->query);
	}
}

static int
hexit( char c )
    {
    if ( c >= '0' && c <= '9' )
	return c - '0';
    if ( c >= 'a' && c <= 'f' )
	return c - 'a' + 10;
    if ( c >= 'A' && c <= 'F' )
	return c - 'A' + 10;
    return 0;           /* shouldn't happen, we're guarded by isxdigit() */
    }

/* Copies and decodes a string.  It's ok for from and to to be the
** same string.
*/
static void
strdecode( char* to, char* from )
{
	for ( ; *from != '\0'; ++to, ++from )
	{
	if ( from[0] == '%' && isxdigit( from[1] ) && isxdigit( from[2] ) )
	    {
	    *to = hexit( from[1] ) * 16 + hexit( from[2] );
	    from += 2;
	    }
	else
	    *to = *from;
	}
	*to = '\0';
}
static void
de_dotdot( char* file )
{
    char* cp;
    char* cp2;
    int l;

    /* Collapse any multiple / sequences. */
    while ( ( cp = strstr( file, "//") ) != (char*) 0 )
	{
	for ( cp2 = cp + 2; *cp2 == '/'; ++cp2 )
	    continue;
	(void) strcpy( cp + 1, cp2 );
	}

    /* Remove leading ./ and any /./ sequences. */
    while ( strncmp( file, "./", 2 ) == 0 )
	(void) strcpy( file, file + 2 );
    while ( ( cp = strstr( file, "/./") ) != (char*) 0 )
	(void) strcpy( cp, cp + 2 );

    /* Alternate between removing leading ../ and removing xxx/../ */
    for (;;)
	{
	while ( strncmp( file, "../", 3 ) == 0 )
	    (void) strcpy( file, file + 3 );
	cp = strstr( file, "/../" );
	if ( cp == (char*) 0 )
	    break;
	for ( cp2 = cp - 1; cp2 >= file && *cp2 != '/'; --cp2 )
	    continue;
	(void) strcpy( cp2 + 1, cp + 4 );
	}

    /* Also elide any xxx/.. at the end. */
    while ( ( l = strlen( file ) ) > 3 &&
	    strcmp( ( cp = file + l - 3 ), "/.." ) == 0 )
	{
	for ( cp2 = cp - 1; cp2 >= file && *cp2 != '/'; --cp2 )
	    continue;
	if ( cp2 < file )
	    break;
	*cp2 = '\0';
	}
}
static void
defang( char* str, char* dfstr, int dfsize )
{
    char* cp1;
    char* cp2;

    for ( cp1 = str, cp2 = dfstr;
	  *cp1 != '\0' && cp2 - dfstr < dfsize - 5;
	  ++cp1, ++cp2 )
	{
	switch ( *cp1 )
	    {
	    case '<':
	    *cp2++ = '&';
	    *cp2++ = 'l';
	    *cp2++ = 't';
	    *cp2 = ';';
	    break;
	    case '>':
	    *cp2++ = '&';
	    *cp2++ = 'g';
	    *cp2++ = 't';
	    *cp2 = ';';
	    break;
	    default:
	    *cp2 = *cp1;
	    break;
	    }
	}
    *cp2 = '\0';
}
int add_response(string_container *resp, char *add)
{
	int len = strlen(add);
	if(!resp->buf)
	{
		resp->size = 1024;
		resp->buf = calloc(1, resp->size);
	}
	while(len > resp->size - resp->len)
	{
		resp->size *= 2;
		resp->buf = realloc(resp->buf, resp->size);
	}
	if(resp->buf)
	{
		resp->len += snprintf(resp->buf+resp->len, resp->size-resp->len, "%s", add);
		return 0;
	}
	return -1;
}

response_line_t g_http_code[] =
{
	{100, "Continue"},{101, "Switching Protocols"},{102, "Processing"},
	
	{200, "OK"},{201, "Created"},{202, "Accepted"},{203, "Non-Authoritative Information"},
	{204, "No Content"},{205, "Reset Content"},{206, "Partial Content"},{207, "Multi-Status"},
	
	{300, "Multiple Choices"},{301, "Moved Permanently"},{302, "Move Temporarily"},{303, "See Other"},
	{304, "Not Modified"},{305, "Use Proxy"},{306, "Switch Proxy"},{307, "Temporary Redirect"},

	{400, "Bad Request"},{401, "Unauthorized"},{402, "Payment Required"},{403, "Forbidden"},
	{404, "Not Found"},{405, "Method Not Allowed"},{406, "Not Acceptable"},{407, "Proxy Authentication Required"},
	{408, "Request Timeout"},{409, "Conflict"},{410, "Gone"},{411, "Length Required"},
	{412, "Precondition Failed"},{413, "Request Entity Too Large"},{414, "Request-URI Too Long"},{415, "Unsupported Media Type"},
	{416, "Requested Range Not Satisfiable"},{417, "Expectation Failed"},{418, "I'm a teapot"},{421, "Too Many Connections"},
	{422, "Unprocessable Entity"},{423, "Locked"},{424, "Failed Dependency"},{425, "Too Early"},
	{426, "Upgrade Required"},{449, "Retry With"},{451, "Unavailable For Legal Reasons"},
	
	{500, "Internal Server Error"},{501, "Not Implemented"},{502, "Bad Gateway"},{503, "Service Unavailable"},
	{504, "Gateway Timeout"},{505, "HTTP Version Not Supported"},{506, "Variant Also Negotiates"},{507, "Insufficient Storage"},
	{509, "Bandwidth Limit Exceeded"},{510, "Not Extended"},

	{600, "Unparseable Response Headers"}
};
int g_http_code_hash_index[] = {0, 3, 11, 19, 46, 56};

char *get_status_code_details(int status)
{
	char *detail = NULL;
	int i = 0;
	int hash_key = status/100;
	int start_index = g_http_code_hash_index[hash_key-1];
	int end_index = 0;//not include end_index
	if(hash_key == sizeof(g_http_code_hash_index)/sizeof(g_http_code_hash_index[0]))
	{
		end_index = sizeof(g_http_code)/sizeof(g_http_code[0]);
	}
	else
	{
		end_index = g_http_code_hash_index[hash_key];
	}
	if(hash_key > 0 && hash_key <= 6)
	{
		for(i = start_index; i < end_index; i++)
		{
			if(status == g_http_code[i].status)
			{
				detail = g_http_code[i].detail;
				break;
			}
		}
	}
	return detail;
}

