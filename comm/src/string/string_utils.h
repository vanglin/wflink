#ifndef _STRING_UTILS_H__
#define _STRING_UTILS_H__
typedef struct
{
	char *key;
	char *val;
}str_line_t;

struct line_t
{
	int lines;
	str_line_t line[1024];
};
struct msg_process_t
{
	char *head;
	int (*func)(void*args,char*head,struct line_t *pstline);
};
int dev_ptr2str(void*pccb,char*ids,int _size);
char*dev_str2ptr(char *ids);
char*dev_strdup(char*src);
int dev_strint(char*src);
int dev_strlong(char*src);

char *skip_blanks(const char *str);
char *get_head(struct line_t *stline, char*key);
int save_line(char *line,char *out);
int ami_line_parse(char*buf,int len,char*sep,char*out);
int commds_parse_do(char*xarg,int len,struct line_t*line);
int head2Ami(struct line_t *pstline,char*buf,int maxlen);

#define dev_atoi(str) dev_strint(str)
#define dev_dup(str) dev_strdup(str)

#endif
