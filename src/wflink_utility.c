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
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <net/if.h>
#include <time.h>
#include <assert.h>
#include <cJSON.h>


#include "wflink.h"
#include "wflink_utility.h"

#define MAC_ADDR_LEN		12
#define MAC_ADDR_DOT_LEN	17

#if 0
int dns_reslove(const char *host, const char *service, struct sockaddr *dst)
{
	struct addrinfo *res = NULL, *ainfo = NULL;
	struct addrinfo hints;
	int error, len=-1;

	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_family = AF_UNSPEC;
	memset(&dst, 0, sizeof(dst));

	error = getaddrinfo(host, service, &hints, &res);
	if ( error != 0 )
	{
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(error));
		return error;
	}

	for ( ainfo = res; ainfo != NULL; ainfo = ainfo->ai_next )
	{
		switch ( ainfo->ai_family)
		{
			case AF_INET6:
			case AF_INET:
				len = dst->size = ainfo->ai_addrlen;
				memcpy(dst, ainfo->ai_addr, len);
				break;
			default:
				break;
		}
	}

	if ( res )
		freeaddrinfo(res);
	return len;
}

time_t trans_str_to_time(char *str)
{
	struct tm time_fields;
	time_t seconds;
	sscanf(str, "%4d%2d%2d%2d%2d%2d", &time_fields.tm_year, &time_fields.tm_mon,
		&time_fields.tm_mday, &time_fields.tm_hour, &time_fields.tm_min, &time_fields.tm_sec);
	printf("%04d-%02d-%02d %02d:%02d:%02d\n", time_fields.tm_year, time_fields.tm_mon, time_fields.tm_mday,
		time_fields.tm_hour, time_fields.tm_min, time_fields.tm_sec);
	time_fields.tm_year -= 1900;
	time_fields.tm_mon -= 1;
	seconds = mktime(&time_fields);
	return seconds;
}
#endif

char* genRandomString(char *dst, int length)
{
	int flag, i;
	char* string;
	srand((unsigned) time(NULL ));
	if(!dst)
	{
		if ((string = (char*)malloc(length)) == NULL )
		{
			return NULL ;
		}
		dst = string;
	}
	memset(dst, 0, length);
	for (i = 0; i < length - 1; i++)
	{
		flag = rand() % 3;
		switch (flag)
		{
			case 0:
				dst[i] = 'A' + rand() % 26;
				break;
			case 1:
		        dst[i] = 'a' + rand() % 26;
		        break;
			case 2:
		        dst[i] = '0' + rand() % 10;
		        break;
			default:
		        dst[i] = 'x';
		        break;
		}
	}
	dst[length - 1] = '\0';
	return dst;
}

int get_cookie(char *cookies, char*key, char*value, int val_len)
{
	char *dupstr = NULL, *ptr = NULL;
	struct line_t obj_cookies = {0};
	int setkey = 1, setvalue = 0;
	int i = 0;
	if(cookies)
	{
		dupstr = strdup(cookies);
		for(ptr=cookies;*ptr>=32;ptr++)
		{
			if(*ptr == ';')
			{
				*ptr = '\0';
				obj_cookies.lines++;
				setkey = 1;
			}
			else if(*ptr == '=')
			{
				*ptr = '\0';
				setvalue = 1;
			}
			else
			{
				if(setkey)
				{
					obj_cookies.line[obj_cookies.lines].key = ptr;
					setkey = 0;
				}
				else if(setvalue)
				{
					obj_cookies.line[obj_cookies.lines].val = ptr;
					setvalue = 0;
				}
			}
		}
		obj_cookies.lines++;
		for(i = 0; i < obj_cookies.lines; i++)
		{
			if(!strncmp(skip_blanks(obj_cookies.line[i].key), key, strlen(key)))
			{
				if(value)
				{
					snprintf(value, val_len, "%s", skip_blanks(obj_cookies.line[i].val));
				}
				break;
			}
		}
		free(dupstr);
	}
	return 0;
}

int get_interface_hwaddr(char *if_name, char *hwaddr, int length)
{
	int sock = -1;
	struct ifreq ifr;
	unsigned char *tmphwaddr = NULL;

	if ( NULL == if_name || NULL == hwaddr )
	{
		DBGPRINT(DEBUG_ERROR, "%s\n", "invalid input paramters");
		return -1;
	}
	
	sock = socket(PF_INET, SOCK_DGRAM, 0);
	if ( sock < 0 ) 
	{
		DBGPRINT(DEBUG_ERROR, "%s\n", "socket open fail");
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, if_name, sizeof(ifr.ifr_name) - 1);
	if ( ioctl(sock, SIOCGIFHWADDR, &ifr) == -1 ) 
	{
		DBGPRINT(DEBUG_ERROR, "%s\n", "ioctl open fail");
		close(sock);
		return -1;
	}
	tmphwaddr = (unsigned char *)ifr.ifr_ifru.ifru_hwaddr.sa_data;
	snprintf(hwaddr, length, "%02x%02x%02x%02x%02x%02x", tmphwaddr[0], tmphwaddr[1], 
		tmphwaddr[2], tmphwaddr[3], tmphwaddr[4], tmphwaddr[5]);
	close(sock);

	return 0;
}

char *stringToCapital(char *string)
{
	int i = 0;

	if ( NULL == string )
		return NULL;

	while(string[i] != '\0')
	{
		if ( string[i] >= 'a' && string[i] <= 'z' )
			string[i] = string[i] - 32;
		i++;
	}
	return string;
}
char *stringToLittle(char *string)
{
	int i = 0;

	if ( NULL == string )
		return NULL;

	while(string[i] != '\0')
	{
		if ( string[i] >= 'A' && string[i] <= 'Z' )
			string[i] = string[i] + 32;
		i++;
	}
	return string;
}
int mac_rm_dot(char *old_mac, char *new_mac)
{
	int i = 0, j = 0, mac_len = MAC_ADDR_DOT_LEN;

	if (old_mac == NULL || new_mac == NULL)
		return -1;
	
	for (i = 0; i < mac_len; i++) {
		if (old_mac[i] != ':')
			new_mac[j++] = old_mac[i];
	}
	new_mac[MAC_ADDR_LEN] = '\0';
	return 0;
}
int mac_add_dot(char *old_mac, char *new_mac)
{
	int i = 0, j = 0;

	if (old_mac == NULL || new_mac == NULL)
		return -1;

	for (i = 0; i < 12; i += 2) {
		new_mac[j] = old_mac[i];
		new_mac[j + 1] = old_mac[i + 1];
		if (j + 2 < 17)
			new_mac[j + 2] = ':';
		j += 3;
	}
	new_mac[17] = '\0';
	
	return 0;
}
int checkHexcharacter (char*keyValue)
{	
	int ret = 0;
	int i = 0;
	char *p = NULL;

	if(keyValue == NULL || '\0' == keyValue[0])
	{
		return -1;
	}
	
	p = keyValue;
	
	for(i = 0; i< strlen(keyValue); i++ )
	{
		if( *(p+i) < 48 || (*(p+i) > 57 && *(p+i)<65) || (*(p+i) > 70 && *(p+i) <97) || *(p+i) > 102)
		{
			return -1;
		}
	}

	return 0;
}
char *getNumbercharacter(char *str)
{
	if(!str)
		return NULL;
	char *ptr = NULL, *ret = NULL;
	char gotit = 0;
	for(ptr=str;*ptr!='\0';ptr++)
	{
		if(gotit == 0 && *ptr >= 48 && *ptr <= 57)
		{
			gotit = 1;
			ret = ptr;
		}
		else if(gotit == 1 && (*ptr < 48 || *ptr > 57))
		{
			*ptr = '\0';
			break;
		}
	}
	return ret;
}

long StringtoInt(char *str, int length)
{
	int charNum = 0;
	long result = 0;
	int i = 0;
    while(length) { 
      	if(str[i]>='0'&&str[i]<='9')
      		charNum = str[i] - 48;
  		else if(str[i]>='a'&&str[i]<='f')
			charNum = str[i] - 'a' + 10;
		else if(str[i]>='A'&&str[i]<='F')
			charNum = str[i] - 'A' + 10;
		//result += charNum * pow(16, length - 1);
		result += charNum << (4 * (length - 1));
		--length;
        ++i;
      }
      return result;
}

