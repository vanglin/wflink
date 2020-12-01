#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>

#include "cjson_parse.h"

static int default_load_config(char *text, cJSON **ret)
{
	char *out;
	cJSON *json=cJSON_Parse(text);
	if(!json)
	{
		printf("text is not json format!\n");return -1;
	}
	out=cJSON_Print(json);
	printf("%s\n",out);
	free(out);
	if(ret)
		*ret = json;
	return 0;
}

int read_json_from_string(char *string, int (*parser)(cJSON *json, void *dst), void *dst, int force)
{
	int res = 0;
	cJSON *json = NULL;
	if(!string)
		return -1;
	if(!force)
	{
		if(!default_load_config(string, &json))
		{
			if(parser)
			{
				res = parser(json, dst);
			}
			cJSON_Delete(json);
		}
	}
	else
	{
		default_load_config(string, &json);
		if(parser)
		{
			res = parser(json, dst);
		}
		cJSON_Delete(json);
	}

	return res;
}

int read_json_from_file(char *filename, int (*parser)(cJSON *json, void *dst), void *dst, int force)
{
	if(!filename)
		return -1;
	int res = 0;
	cJSON *json = NULL;
	FILE *myappcfg = fopen(filename, "r");
	int tmp_size = 128 * 1024;
	char *tmp=malloc(tmp_size);
	if(!tmp)
		return -1;
	memset(tmp, 0, tmp_size);
	if (NULL == myappcfg && !force)
	{
		printf("Error: can't open %s\n", filename);
		free(tmp);
		return -1;
	}

	if(myappcfg)
	{
		fread(tmp,tmp_size,1,myappcfg);	
		fclose(myappcfg);
	}
	
	if(!force)
	{
		if(!default_load_config(tmp, &json))
		{
			if(parser)
			{
				res = parser(json, dst);
			}
			cJSON_Delete(json);
		}
	}
	else
	{
		default_load_config(tmp, &json);
		if(parser)
		{
			res = parser(json, dst);
		}
		cJSON_Delete(json);
	}

	free(tmp);
	return res;
}

