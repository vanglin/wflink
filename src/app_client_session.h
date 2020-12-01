#ifndef __APP_CLIENT_SESSION_H__
#define __APP_CLIENT_SESSION_H__

#include <cJSON.h>

#define ACS_ID_COOKIE "SessionID_R3"
#define MAX_LOGIN_ACCOUNT 4

int app_client_ctx_init(int max_session);
int acs_handle_login_challenge(cJSON *jsonSend, char *username, char *first_nonce);
int acs_handle_authentication_request(cJSON *jsonSend, char *client_proof_hex_string, char *final_nonce, char **acs_id);
void *get_acs_by_acs_id(char *acs_id);

#endif
