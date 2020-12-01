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
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>
#include <assert.h>
#include <cJSON.h>

#include <openssl/hmac.h> 
#include <openssl/evp.h> 
#include <openssl/engine.h> 
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include "wflink.h"
#include "wflink_utility.h"

#define SALT_LEN    32// 32 bytes - 256 bits 
#define KEY_LEN   32
#define NONCE_LEN 32
#define ITERATION   1000 
#define CLIENT_KEY "Client Key"
#define SERVER_KEY "Server Key"
#define MAX_LOGIN_FAIL_TIMES 3

#define ACS_ERROR_CATEGORY_OK "ok"
#define ACS_ERROR_CATEGORY_THREE_TIME_ERR "Three_time_err"
#define ACS_ERROR_CATEGORY_DUPLICATE_LOGIN "Duplicate_login"
#define ACS_ERROR_CATEGORY_TOO_MANY_USER "Too_Many_user"
#define ACS_ERROR_CATEGORY_USER_PASS_ERR "user_pass_err"
#define ACS_ERROR_CATEGORY_TOKEN_EXPIRE "Token_Expire"

enum rsa_file_type_e
{
	RSA_FILE_CRT,
	RSA_FILE_KEY,
	RSA_FILE_PEM
};

typedef struct
{
	unsigned char islogin;
	unsigned char retry;
	char server_nonce[2*NONCE_LEN+1];
	unsigned char server_key[EVP_MAX_MD_SIZE];
	unsigned char stored_key[EVP_MAX_MD_SIZE];
	unsigned int server_key_len;
	unsigned int stored_key_len;
	unsigned int first_nonce_len;
	char username[129];	//index
	char SessionID_R3[129];
}app_client_session;

typedef struct
{
	sig_mutex_t lock;
	struct list_cache_t app_client_sessions;
}client_session_ctx;

struct mt_s
{
	const EVP_MD *digest;
	unsigned char *(*mfunc)(const unsigned char *d, size_t n, unsigned char *md);
	unsigned int md_len;
};

struct mt_s mt_sha256 = {0};

client_session_ctx g_app_client_ctx;
int app_client_ctx_init(int max_session)
{
	sig_mutex_init(&g_app_client_ctx.lock, NULL);
	init_list_cache(&g_app_client_ctx.app_client_sessions, max_session, sizeof(app_client_session), NULL, NULL);
	mt_sha256.digest = EVP_sha256();
	mt_sha256.mfunc = SHA256;
	mt_sha256.md_len = SHA256_DIGEST_LENGTH;
	return 0;
}

app_client_session *alloc_acs()
{
	app_client_session *ret = NULL;
	sig_mutex_lock(&g_app_client_ctx.lock);
	ret = (app_client_session *)list_cache_alloc(&g_app_client_ctx.app_client_sessions);
	sig_mutex_unlock(&g_app_client_ctx.lock);
	if(ret)
	{
		memset(ret, 0, sizeof(*ret));
	}
	return ret;
}

/* Return value:
 * 0 - will detatch and release als resource
 * 1 - will return als resource's data
 * others - do nothing
 */
static int acs_username_cmp_cb(char *data, void *args)
{
	int ret = -1;
	app_client_session *acs = (app_client_session *)data;
	char *username = (char *)args;
	if(!strncmp(acs->username, username, strlen(username)))
	{
		ret = 1;
	}
	return ret;
}
static int acs_server_nonce_cmp_cb(char *data, void *args)
{
	int ret = -1;
	app_client_session *acs = (app_client_session *)data;
	char *server_nonce = (char *)args;
	if(!strncmp(acs->server_nonce, server_nonce, strlen(server_nonce)))
	{
		ret = 1;
	}
	return ret;
}
static int acs_SessionID_R3_cmp_cb(char *data, void *args)
{
	int ret = -1;
	app_client_session *acs = (app_client_session *)data;
	char *SessionID_R3 = (char *)args;
	if(acs->islogin && !strncmp(acs->SessionID_R3, SessionID_R3, strlen(SessionID_R3)))
	{
		ret = 1;
	}
	return ret;
}
app_client_session *find_acs_by_attr(int (*excute_func)(char *data, void *args), void *args)
{
	app_client_session *ret = NULL;
	sig_mutex_lock(&g_app_client_ctx.lock);
	ret = (app_client_session *)list_cache_overlap(&g_app_client_ctx.app_client_sessions, excute_func, args);
	sig_mutex_unlock(&g_app_client_ctx.lock);
	return ret;
}

void hex_print(unsigned char *p, int len)
{
    for (; len--; p++)
        printf("%02X", *p);
    printf("\n");
}

void hexlify(char *dst, int size, unsigned char *src, int len)
{
	int i = 0;
	for(i = 0; i < len && 2*i+1 < size; i++)
	{
		snprintf(dst+2*i, 3, "%02x", src[i]);
	}
}
void unhexlify(unsigned char *dst, int size, char *src)
{
	int i = 0;
	int cell = 2;
	int len = strlen(src);
	for(i = 0; i < len/cell && i < size; i++)
	{
		dst[i] = (unsigned char)StringtoInt(src+i*cell, cell);
	}
}

static int get_passwd_by_username(char *username, char *passwd, int passwd_size)
{
	// !!! get_passwd_by_username [not done]
	snprintf(passwd, passwd_size, "%s", username);
	return 0;
}
static int get_rsainfo_by_username(char *username, char *name, int name_size, enum rsa_file_type_e flag)
{
	// !!! get_rsainfo_by_username [not done]
	switch(flag)
	{
		case RSA_FILE_CRT:
			snprintf(name, name_size, "%s.%s", "/etc/ssl/test-root-ca", "crt");
			break;
		case RSA_FILE_KEY:
			snprintf(name, name_size, "%s.%s", "/etc/ssl/test-root-ca", "key");
			break;
		case RSA_FILE_PEM:
			snprintf(name, name_size, "%s.%s", "/etc/ssl/test-root-ca", "pem");
			break;
		default:
			break;
	}
	return access(name, 0);
}
int acs_handle_login_challenge(cJSON *jsonSend, char *username, char *first_nonce)
{
	unsigned char salt[SALT_LEN] = {0};
	unsigned char salt_password[KEY_LEN] = {0};
	unsigned char client_key[EVP_MAX_MD_SIZE] ={0};
	unsigned char server_key[EVP_MAX_MD_SIZE] = {0};
	unsigned char stored_key[EVP_MAX_MD_SIZE] = {0};
	char server_nonce[2*NONCE_LEN+1] = {0};
	char randcharecter[NONCE_LEN+1] = {0};
	char cur_csrf_token[64] = {0};
	char passwd[128] = {0};
	char salt_hex_string[2*SALT_LEN+1] = {0};
	char *errorCategory = ACS_ERROR_CATEGORY_OK;
	int ret = 0, errcode = 0;
	app_client_session *acs = NULL;
	
	acs = find_acs_by_attr(acs_username_cmp_cb, (void *)username);
	if(!acs)
	{
		// if the acs doesn't exists, alloc it.
		acs = alloc_acs();
		if(acs)
		{
			// set username
			snprintf(acs->username, sizeof(acs->username), "%s", username);
		}
		else
		{
			// if alloc failed, response errorCategory 'Too_Many_user'
			errorCategory = ACS_ERROR_CATEGORY_TOO_MANY_USER;
			errcode= 4784229;
			goto end;
		}
	}
	if(acs->islogin)
	{
		// response errorCategory 'Duplicate_login'
		errorCategory = ACS_ERROR_CATEGORY_DUPLICATE_LOGIN;
		errcode= 4784229;
		goto end;
	}
	get_passwd_by_username(username, passwd, sizeof(passwd));
	genRandomString(randcharecter, sizeof(randcharecter));
	snprintf(server_nonce, sizeof(server_nonce), "%s%s", first_nonce, randcharecter);
	acs->first_nonce_len = strlen(first_nonce);
	RAND_bytes(salt, sizeof(salt));
	hexlify(salt_hex_string, sizeof(salt_hex_string), salt, sizeof(salt));
	DBGPRINT(DEBUG_INFO, "salt = ");
	hex_print(salt, sizeof(salt));
	
	ret = PKCS5_PBKDF2_HMAC(passwd, strlen(passwd), salt, sizeof(salt), ITERATION, mt_sha256.digest, sizeof(salt_password), salt_password);
	if(!ret)
	{
		// never goto here
		assert(0);
		return -1;
	}

	HMAC(mt_sha256.digest, CLIENT_KEY, strlen(CLIENT_KEY), salt_password, sizeof(salt_password), client_key, NULL);
	HMAC(mt_sha256.digest, SERVER_KEY, strlen(SERVER_KEY), salt_password, sizeof(salt_password), server_key, &acs->server_key_len);
	mt_sha256.mfunc(client_key, mt_sha256.md_len, stored_key);

	// store server_key, stored_key, server_nonce
	memcpy(acs->server_nonce, server_nonce, sizeof(acs->server_nonce));
	memcpy(acs->server_key, server_key, sizeof(acs->server_key));
	memcpy(acs->stored_key, stored_key, sizeof(acs->stored_key));
	acs->stored_key_len = mt_sha256.md_len;
	// response with salt, ITERATION, server_nonce
	// update csrf_token

	DBGPRINT(DEBUG_INFO, "salt_password = ");
	hex_print(salt_password, sizeof(salt_password));
	DBGPRINT(DEBUG_INFO, "client_key = ");
	hex_print(client_key, mt_sha256.md_len);
	DBGPRINT(DEBUG_INFO, "store_key = ");
	hex_print(stored_key, acs->stored_key_len);
end:
	set_g_csrf_token();
	get_g_csrf_token(cur_csrf_token, sizeof(cur_csrf_token));
	cJSON_AddStringToObject(jsonSend, "csrf_param", "authenticity_token");
	cJSON_AddStringToObject(jsonSend, "csrf_token", cur_csrf_token);
	cJSON_AddNumberToObject(jsonSend, "err", errcode);
	cJSON_AddStringToObject(jsonSend, "errorCategory", errorCategory);
	cJSON_AddStringToObject(jsonSend, "salt", salt_hex_string);
	cJSON_AddNumberToObject(jsonSend, "iterations", ITERATION);
	cJSON_AddStringToObject(jsonSend, "servernonce", server_nonce);
	return 0;
}

#define XOR(str1,str2,dst,len) \
do \
{ \
	int i = 0; \
	for(i = 0; i < len; i++) \
	{ \
		dst[i] = str1[i] ^ str2[i]; \
	} \
}while(0)

// !!! add_scram_extended_rsa need openssl and the prikey need store in acs [not done]
void add_scram_extended_rsa(cJSON *jsonSend, app_client_session *acs)
{
	char crt_file[64] = {0}, pubkey_file[64] = {0}, modulesNexponent_file[64] = {0}, cmd[128] = {0};
	char rsa_pubkey_signature_hex_string[2*EVP_MAX_MD_SIZE+1] = {0};
	unsigned char rsa_pubkey_signature[EVP_MAX_MD_SIZE] = {0};
	enum rsa_file_type_e certificate_type = RSA_FILE_CRT;
	FILE *fp = NULL;
	long length = 0L;
	char line[1024] = {0}, modulus[513] = {0}, exponent[8] = {0};
	char *buffer = NULL, *ptr = NULL;
	int getModulus = 0, i = 0, j = 0;
	unsigned int rsa_pubkey_signature_len = 0;
	if(get_rsainfo_by_username(acs->username, crt_file, sizeof(crt_file), certificate_type))
		return;
	snprintf(pubkey_file, sizeof(pubkey_file), "/tmp/%s_public.key", acs->username);
	snprintf(modulesNexponent_file, sizeof(modulesNexponent_file), "/tmp/%s_ne", acs->username);
	snprintf(cmd, sizeof(cmd), "openssl x509 -in %s -pubkey -noout > %s", crt_file, pubkey_file);
	system(cmd);
	snprintf(cmd, sizeof(cmd), "openssl rsa -in %s -pubin -inform PEM -text -noout > %s", pubkey_file, modulesNexponent_file);
	system(cmd);
	fp = fopen(pubkey_file, "r");
	if(!fp)
		goto end;
	fseek(fp,0L,SEEK_END);
	length = ftell(fp);
	fseek(fp,0L,SEEK_SET);
	buffer = malloc(length);
	memset(buffer, 0, length);
	while(fgets(line, sizeof(line), fp))
	{
		if(!strstr(line, "PUBLIC KEY"))
		{
			if('\n' == line[strlen(line)-1] || '\r' == line[strlen(line)-1])
				line[strlen(line)-1] = '\0';
			strcat(buffer, line);
		}
	}
	DBGPRINT(DEBUG_TRACE, "%s\n", buffer);
	HMAC(mt_sha256.digest, acs->server_key, acs->server_key_len, buffer, strlen(buffer), rsa_pubkey_signature, &rsa_pubkey_signature_len);
	fclose(fp);
	free(buffer);
	buffer = NULL;
	fp = fopen(modulesNexponent_file, "r");
	if(!fp)
		goto end;
	fseek(fp,0L,SEEK_END);
	length = ftell(fp);
	fseek(fp,0L,SEEK_SET);
	buffer = malloc(length);
	memset(buffer, 0, length);
	while(fgets(line, sizeof(line), fp))
	{
		if(strstr(line, "Modulus:"))
		{
			getModulus = 1;
		}
		else if(ptr = strstr(line, "Exponent:"))
		{
			getModulus = 0;
			snprintf(exponent, sizeof(exponent), "%06x", atoi(ptr+strlen("Exponent:")));
		}
		else if(getModulus)
		{
			if('\n' == line[strlen(line)-1] || '\r' == line[strlen(line)-1])
				line[strlen(line)-1] = '\0';
			strcat(buffer, skip_blanks(line));
		}
	}
	DBGPRINT(DEBUG_TRACE, "%s\n", buffer);
	for(i = 0; i < strlen(buffer); i++)
	{
		if(':' != buffer[i])
		{
			modulus[j++] = buffer[i];
			if(j == sizeof(modulus))
				break;
		}
	}
	fclose(fp);
	free(buffer);
	buffer = NULL;
	hexlify(rsa_pubkey_signature_hex_string, sizeof(rsa_pubkey_signature_hex_string), rsa_pubkey_signature, rsa_pubkey_signature_len);
	DBGPRINT(DEBUG_TRACE, "rsapubkeysignature=%s, rsan=%s, rsae=%s\n", rsa_pubkey_signature_hex_string, modulus, exponent);
	cJSON_AddStringToObject(jsonSend, "rsapubkeysignature", rsa_pubkey_signature_hex_string);
	cJSON_AddStringToObject(jsonSend, "rsan", modulus);
	cJSON_AddStringToObject(jsonSend, "rsae", exponent);
end:
	unlink(pubkey_file);
	unlink(modulesNexponent_file);
	WF_FREE(buffer);
}
int acs_handle_authentication_request(cJSON *jsonSend, char *client_proof_hex_string, char *final_nonce, char **acs_id)
{
	char auth_message[6*NONCE_LEN+3] = {0};
	char server_signature_hex_string[2*EVP_MAX_MD_SIZE+1] = {0};
	char cur_csrf_token[64] = {0};
	unsigned char client_signature[EVP_MAX_MD_SIZE] ={0};
	unsigned char client_signature_xor_proof[EVP_MAX_MD_SIZE] ={0};
	unsigned char calc_stored_key[EVP_MAX_MD_SIZE] ={0};
	unsigned char server_signature[EVP_MAX_MD_SIZE] ={0};
	unsigned char client_proof[EVP_MAX_MD_SIZE] ={0};
	char *errorCategory = ACS_ERROR_CATEGORY_OK;
	app_client_session *acs = NULL;
	int errcode = 0, count = 0;
	unsigned int server_signature_len = 0;
	acs = find_acs_by_attr(acs_server_nonce_cmp_cb, (void *)final_nonce);
	if(!acs)
	{
		DBGPRINT(DEBUG_ERROR, "acs not found, final_nonce:%s\n", final_nonce);
		errorCategory = ACS_ERROR_CATEGORY_USER_PASS_ERR;
		errcode= 4784229;
		goto end;
	}
	unhexlify(client_proof, sizeof(client_proof), client_proof_hex_string);
	snprintf(auth_message, sizeof(auth_message), "%.*s,%s,%s", acs->first_nonce_len, final_nonce, final_nonce, final_nonce);
	HMAC(mt_sha256.digest, auth_message, strlen(auth_message), acs->stored_key, acs->stored_key_len, client_signature, NULL);
	XOR(client_signature, client_proof, client_signature_xor_proof, mt_sha256.md_len);
	mt_sha256.mfunc(client_signature_xor_proof, mt_sha256.md_len, calc_stored_key);
	DBGPRINT(DEBUG_INFO, "auth_message = %s\n", auth_message);
	DBGPRINT(DEBUG_INFO, "client_sign = ");
	hex_print(client_signature, mt_sha256.md_len);
	DBGPRINT(DEBUG_INFO, "client_proof = ");
	hex_print(client_proof, mt_sha256.md_len);
	DBGPRINT(DEBUG_INFO, "stored_key = ");
	hex_print(acs->stored_key, acs->stored_key_len);
	DBGPRINT(DEBUG_INFO, "calc_stored_key = ");
	hex_print(calc_stored_key, mt_sha256.md_len);
	if(memcmp(acs->stored_key, calc_stored_key, acs->stored_key_len))
	{
		errorCategory = ACS_ERROR_CATEGORY_USER_PASS_ERR;
		errcode= 4784229;
		goto end;
	}
	HMAC(mt_sha256.digest, auth_message, strlen(auth_message), acs->server_key, acs->server_key_len, server_signature, &server_signature_len);
	
end:
	set_g_csrf_token();
	get_g_csrf_token(cur_csrf_token, sizeof(cur_csrf_token));
	cJSON_AddStringToObject(jsonSend, "csrf_param", "authenticity_token");
	cJSON_AddStringToObject(jsonSend, "csrf_token", cur_csrf_token);
	cJSON_AddNumberToObject(jsonSend, "err", errcode);
	if(0 == errcode)
	{
		acs->islogin = 1;
		genRandomString(acs->SessionID_R3, sizeof(acs->SessionID_R3));
		if(acs_id) *acs_id = acs->SessionID_R3;
		hexlify(server_signature_hex_string, sizeof(server_signature_hex_string), server_signature, server_signature_len);
		cJSON_AddStringToObject(jsonSend, "serversignature", server_signature_hex_string);
		cJSON_AddNumberToObject(jsonSend, "level", 1);
		add_scram_extended_rsa(jsonSend, acs);
	}
	else
	{
		if((count = ++acs->retry) > MAX_LOGIN_FAIL_TIMES)
		{
			errorCategory = ACS_ERROR_CATEGORY_THREE_TIME_ERR;
			acs->retry = 0;
		}
		cJSON_AddStringToObject(jsonSend, "errorCategory", errorCategory);
		cJSON_AddNumberToObject(jsonSend, "count", count);
		cJSON_AddNumberToObject(jsonSend, "maxfailtimes", MAX_LOGIN_FAIL_TIMES);
	}
	return errcode;
}

void *get_acs_by_acs_id(char *acs_id)
{
	app_client_session *acs = NULL;
	if(acs_id && acs_id[0] != '\0')
	{
		acs = find_acs_by_attr(acs_SessionID_R3_cmp_cb, (void *)acs_id);
	}
	return (void *)acs;
}
