#ifndef __WFLINK_UTILITY_H__
#define __WFLINK_UTILITY_H__

#if 0
#include <sys/socket.h>
#include <time.h>
int dns_reslove(const char *host, const char *service, struct sockaddr *dst);
time_t trans_str_to_time(char *str)
#endif

char* genRandomString(char *dst, int length);
static inline char *intIntoString(int number, char *slen, int size)
{
	if(slen)
	{
		snprintf(slen, size, "%d", number);
	}
	return slen;
}
int get_cookie(char *cookies, char*key, char*value, int val_len);
int get_interface_hwaddr(char *if_name, char *hwaddr, int length);
char *stringToCapital(char *string);
char *stringToLittle(char *string);
int mac_rm_dot(char *old_mac, char *new_mac);
int mac_add_dot(char *old_mac, char *new_mac);
int checkHexcharacter (char*keyValue);
char *getNumbercharacter(char *str);
long StringtoInt(char *str, int length);

#endif
