#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include "string_utils.h"
int dev_ptr2str(void*pccb,char*ids,int _size)
{
	return snprintf(ids,_size,"%ld",pccb);
}
char*dev_str2ptr(char *ids)
{
   long ptr_int=atol(ids);
   return (char*)(ptr_int);
}

char *dev_bool(int val)
{
  return val?"yes":"no";
}
int strlen_zero(const char *s)
{
        return (!s || (*s == '\0'));
}

char*dev_strdup(char*src)
{
	if(strlen_zero(src))
	{
		return NULL;
	}
	return strdup(src);
}
int dev_strint(char*src)
{
	if(strlen_zero(src))
	{
		return 0;
	}
	return atoi(src);
}
int dev_strlong(char*src)
{
	if(strlen_zero(src))
	{
		return 0;
	}
	return atol(src);
}
char *skip_sep(const char *str,char sep)
{
        while (*str && *str == sep)
                str++;
        return (char *)str;
}

char *skip_blanks(const char *str)
{
        while (*str && *str < 33)
                str++;
        return (char *)str;
}

int save_line(char *line,char *out)
{
	str_line_t *dbstr=NULL;
	struct line_t *pline=(struct line_t *)out;
	char *colon=NULL;
	if(!line||!out)
	{
		return -1;
	}
	dbstr= &(pline->line[pline->lines++]);
	dbstr->key=line;
	dbstr->val=NULL;
	if(colon=strstr(dbstr->key,": "))
	{
		*colon='\0';
		dbstr->val=skip_blanks(colon+2);
	}
	return 0;
}



char *get_head(struct line_t *stline, char*key)
{
	int i =0;
	str_line_t *ptr=NULL;
	if(!stline||!key)
	{
		return NULL;
	}
	for(i=0;i<stline->lines;i++)
	{
		ptr=&(stline->line[i]);
		if(ptr->key&&!strcasecmp(ptr->key,key))
		{
			return ptr->val;
		}
	}
	return NULL;
}

int ami_line_parse(char*buf,int len,char*sep,char*out)
{
	int left=0;
	char *tmp=buf;
	char *pos=NULL;
	int seplen=strlen(sep);
	while(tmp&&(pos=strstr(tmp,sep)))
	{
		*pos='\0';
		save_line(tmp,out);		
		tmp = skip_blanks(pos+seplen);
		if (tmp- buf >= len)
		{
		    tmp=NULL;
			break;
		}
	}
	save_line(tmp,out);
	return 0;
}
int head2Ami(struct line_t *pstline,char*buf,int maxlen)
{
	int i =0;
	int len =0;
	if(!pstline||!buf)
	{
		return 0;
	}
	str_line_t*ptr=pstline->line;
	for(i=0;i<pstline->lines;i++)
	{
		if(maxlen<=len)
		{
			break;
		}
		if(ptr->key)
		{
			len += snprintf(buf+len,maxlen-len,"%s: %s\r\n",ptr->key,ptr->val?ptr->val:"");
		}
		ptr++;
	}
	if(maxlen > (len+4))
	{
		len += snprintf(buf+len,maxlen-len,"\r\n\r\n");
	}	
	return len;	
}
int commds_parse_do(char*xarg,int len,struct line_t*line)
{
	int qoute_flags=0;
    int i =0;
	char *tmp=NULL;
	char *end=NULL;
	str_line_t *ptr=NULL;
	line->lines=0;
	tmp = xarg;
	char *header=xarg;
	for(i=0;i<len;i++)
	{
		if(end)
		{
			tmp = xarg;
			end=NULL;
		}
		if(*xarg=='\'')
		{
			if(qoute_flags)
			{
				if(qoute_flags==1)
				{
					qoute_flags=0;
				}
			}
			else
			{
				qoute_flags=1;
			}
		}
		else if(*xarg=='\"')
		{
			if(qoute_flags)
			{
				if(qoute_flags==2)
				{
					qoute_flags=0;
				}
			}
			else
			{
				qoute_flags=2;
			}
		}
		else if(*xarg==';')
		{
			if(!qoute_flags)
			{
				*xarg='\0';
				if(tmp==xarg)
				{
					break;
				}
				
				ptr=&(line->line[line->lines++]);
				ptr->key=tmp;
				ptr->val=NULL;
				if(tmp=strstr(tmp,": "))
				{
					*tmp='\0';
					ptr->val=tmp+2;
				}
				end = xarg;
				tmp=xarg+1;
 			}
		}
		xarg++;
	}
	if(!line->lines)
	{
		tmp =header;
		ptr=&(line->line[line->lines++]);
		ptr->key=tmp;
		ptr->val=NULL;
		if(tmp=strstr(tmp,": "))
		{
			*tmp='\0';
			ptr->val=tmp+2;
		}
	}
	return 0;
}

