#ifndef __CJSON_PARSE_H__
#define __CJSON_PARSE_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cJSON.h"

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

int read_json_from_string(char *string, int (*parser)(cJSON *json, void *dst), void *dst, int force);
int read_json_from_file(char *filename, int (*parser)(cJSON *json, void *dst), void *dst, int force);

#endif
