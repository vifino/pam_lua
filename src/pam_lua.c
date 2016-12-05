// pam_lua: Scriptable PAM module using Lua
// Author: Adrian "vifino" Pistol

// Project includes
#include <bootcode.h>
// Generic includes
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
// PAM
#include <security/pam_appl.h>
#include <security/pam_modules.h>
// Lua
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

////
// Helpers
////

// varargs concat from http://stackoverflow.com/a/11394336 because i don't like varargs much.
static char* concat(int count, ...) {
	va_list ap;
	int i;

	// Find required length to store merged string
	size_t len = 1; // room for \0
	va_start(ap, count);
	for(i=0 ; i<count ; i++)
		len += strlen(va_arg(ap, const char*));
	va_end(ap);

	// Allocate memory to concat strings
	char* merged = calloc(len, sizeof(char));
	if (merged == NULL)
		return NULL;
	int null_pos = 0;

	// Actually concatenate strings
	va_start(ap, count);
	for(i=0 ; i<count ; i++)
	{
		char *s = va_arg(ap, char*);
		strcpy(merged+null_pos, s);
		null_pos += strlen(s);
	}
	va_end(ap);

	return merged;
}

////
// PAM helpers
////

// I/O
static int converse(const pam_handle_t *pamh, int nargs, struct pam_message **message, struct pam_response **response) {
	struct pam_conv *conv;

	int retval = pam_get_item(pamh, PAM_CONV, (const void**)&conv);
	if (retval == PAM_SUCCESS) {
		retval = conv->conv(nargs, (const struct pam_message**)message, response, conv->appdata_ptr);
	}

	return retval;
}

static int pam_readline(const pam_handle_t *pamh, int visible, const char* str, char* *res) {
	// Prepare mesg structs
	struct pam_message mesg[1], *pmesg[1];
	pmesg[0] = &mesg[0];

	if (visible != 0) {
		mesg[0].msg_style = PAM_PROMPT_ECHO_ON;
	} else {
		mesg[0].msg_style = PAM_PROMPT_ECHO_OFF;
	}

	mesg[0].msg = str;

	// Ask
	int retval;
	struct pam_response *resp;
	if ((retval = converse(pamh, 1, pmesg, &resp)) != PAM_SUCCESS) {
		return retval;
	}

	if (resp) {
		char* tres = resp[0].resp;
		*res = calloc(strlen(tres)+1, sizeof(char));
		if (*res == NULL)
			return PAM_BUF_ERR; // allocation failure
		strcpy(*res, tres);
		resp[0].resp = NULL;
		return PAM_SUCCESS;
	}
	return PAM_CONV_ERR;
}

static int pam_info(const pam_handle_t *pamh, const char* str) {
	// Prepare mesg structs
	struct pam_message mesg[1], *pmesg[1];
	pmesg[0] = &mesg[0];

	mesg[0].msg_style = PAM_TEXT_INFO;
	mesg[0].msg = str;

	// Display text
	int retval;
	struct pam_response *resp;
	if ((retval = converse(pamh, 1, pmesg, &resp)) != PAM_SUCCESS) {
		return retval;
	}
	return PAM_SUCCESS;
}

static int pam_error(const pam_handle_t *pamh, const char* str) {
	// Prepare mesg structs
	struct pam_message mesg[1], *pmesg[1];
	pmesg[0] = &mesg[0];

	mesg[0].msg_style = PAM_ERROR_MSG;
	mesg[0].msg = str;

	// send error
	int retval;
	struct pam_response *resp;
	if ((retval = converse(pamh, 1, pmesg, &resp)) != PAM_SUCCESS) {
		return retval;
	}
	return PAM_SUCCESS;
}

// Items
#define PAM_LUA_PITYPE_STRING 1
#define PAM_LUA_PITYPE_CONV 2
#define PAM_LUA_PITYPE_FAIL_DELAY 3

static int pam_get_itype(const char* iname, int *type) {
	*type = PAM_LUA_PITYPE_STRING;
	if (strcmp(iname, "service"))
		return PAM_SERVICE;
	if (strcmp(iname, "user"))
		return PAM_USER;
	if (strcmp(iname, "user_prompt"))
		return PAM_USER_PROMPT;
	if (strcmp(iname, "tty"))
		return PAM_TTY;
	if (strcmp(iname, "ruser"))
		return PAM_RUSER;
	if (strcmp(iname, "rhost"))
		return PAM_RHOST;
	if (strcmp(iname, "authtok"))
		return PAM_AUTHTOK;
	if (strcmp(iname, "oldauthtok"))
		return PAM_OLDAUTHTOK;
	if (strcmp(iname, "conv")) {
		*type = PAM_LUA_PITYPE_CONV;
		return PAM_CONV;
	}
	if (strcmp(iname, "fail_delay")) {
		*type = PAM_LUA_PITYPE_FAIL_DELAY;
		return PAM_FAIL_DELAY;
	}
	if (strcmp(iname, "xdisplay"))
		return PAM_XDISPLAY;
	if (strcmp(iname, "xauthdata"))
		return PAM_XAUTHDATA;
	if (strcmp(iname, "authtok_type"))
		return PAM_AUTHTOK_TYPE;
}

////
// Lua helpers
////
static void ltable_push_str(lua_State* L, const char* key, char* value) {
	lua_pushstring(L, key);
	lua_pushstring(L, value);
	lua_settable(L, -3);
}
static void ltable_push_str_int(lua_State* L, const char* key, int value) {
	lua_pushstring(L, key);
	lua_pushnumber(L, value);
	lua_settable(L, -3);
}
static void ltable_push_str_func(lua_State* L, const char* key, lua_CFunction func) {
	lua_pushstring(L, key);
	lua_pushcfunction(L, func);
	lua_settable(L, -3);
}

static void ltable_push_str_bool(lua_State* L, const char* key, int value) {
	lua_pushstring(L, key);
	lua_pushboolean(L, value);
	lua_settable(L, -3);
}

////
// Lua bindings
////

static pam_handle_t *_pamhandle;

// I/O
static int pam_lua_info(lua_State* L) {
	const char* text = luaL_checkstring(L, 1);
	lua_pushnumber(L, pam_info(_pamhandle, text));
	return 1;
}

static int pam_lua_error(lua_State* L) {
	const char* text = luaL_checkstring(L, 1);
	lua_pushnumber(L, pam_error(_pamhandle, text));
	return 1;
}

static int pam_lua_readline(lua_State* L) {
	int visible = lua_toboolean(L, 1);

	char* res;
	int ret;
	if (lua_isstring(L, 2)) {
		ret = pam_readline(_pamhandle, visible, lua_tostring(L, 2), &res);
	} else {
		ret = pam_readline(_pamhandle, visible, "", &res);
	}

	if (ret != PAM_SUCCESS) {
		lua_pushnil(L);
		lua_pushnumber(L, ret);
		return 2;
	}
	lua_pushstring(L, res);
	free(res);
	return 1;
}

// Get user
static int pam_lua_get_user(lua_State* L) {
	const char* prompt = NULL;
	if (lua_isstring(L, 1))
		prompt = lua_tostring(L, 1);

	const char* user;
	int ret = pam_get_user(_pamhandle, &user, prompt);

	if (ret != PAM_SUCCESS) {
		lua_pushnil(L);
		lua_pushnumber(L, ret);
		return 2;
	}

	lua_pushstring(L, user);
	return 1;
}

// env
static int pam_lua_getenv(lua_State* L) {
	const char* val = pam_getenv(_pamhandle, luaL_checkstring(L, 1));
	if (val == NULL) {
		lua_pushnil(L);
	} else {
		lua_pushstring(L, val);
	}
	return 1;
}

static int pam_lua_setenv(lua_State* L) {
	const char* key = luaL_checkstring(L, 1);
	if (lua_isnil(L, 2)) {
		char* str = concat(2, key, "=");
		if (str == NULL)
			return luaL_error(L, "memory allocation failure");
		int ret = pam_putenv(_pamhandle, str);
		free(str);
		lua_pushboolean(L, ret == PAM_SUCCESS);
		return 1;
	}
	const char* value = luaL_checkstring(L, 2);
	char* str = concat(3, key, "=", value);
	if (str == NULL)
			return luaL_error(L, "memory allocation failure");
	int ret = pam_putenv(_pamhandle, str);
	free(str);
	lua_pushboolean(L, ret == PAM_SUCCESS);
	return 1;
}

// items
static int pam_lua_get_item(lua_State* L) {
	const char* iname = luaL_checkstring(L, 1);
	
	// get identifier and type of return value
	int itype;
	const int itype_no = pam_get_itype(iname, &itype);

	// get stuff
	const void* data;
	int ret = pam_get_item(_pamhandle, itype_no, &data);
	if (ret != PAM_SUCCESS)
		return luaL_error(L, "could not get item");

	// alright, now we need to return this stuff
	if (data == NULL) {
		lua_pushnil(L);
		return 1;
	}

	switch(itype) {
		case PAM_LUA_PITYPE_STRING:
			lua_pushstring(L, (char*)data);
			break;
		default:
			luaL_error(L, "couldn't convert non-string item");
	}
	return 1;
}

static int pam_lua_set_item(lua_State* L) {
	const char* iname = luaL_checkstring(L, 1);

	// get identifier and type of return value
	int itype;
	const int itype_no = pam_get_itype(iname, &itype);

	// get data
	void* data;
	switch(itype) {
		case PAM_LUA_PITYPE_STRING:
			data = (void*) luaL_checkstring(L, 2);
			break;
		default:
			return luaL_error(L, "item is not type string, can not set");
	}

	// set data
	int ret = pam_set_item(_pamhandle, itype_no, data);
	if (ret != PAM_SUCCESS)
		return luaL_error(L, "could not set item");

	return 0;
}

////
// pam_lua handlers
////

// Main magic function, it is the backbone of all other hooks.
static int pam_lua_handler(char* pam_hook_type, pam_handle_t *pamh, int flags, int argc, const char **argv) {
	// Set global pamhandle to this one.
	_pamhandle = pamh;
	// Init Lua state
	lua_State* L = luaL_newstate();

	// Our PAM bindings.
	lua_newtable(L);
	{
		// PAM call type
		ltable_push_str(L, "handler", pam_hook_type);
		char* pam_mod_type;

		if (!(strcmp(pam_hook_type, "setcred") || strcmp(pam_hook_type, "authenticate"))) {
				pam_mod_type = "auth";
		} else if (strcmp(pam_hook_type, "acct_mgnt") == 0) {
				pam_mod_type = "account";
		} else if (!(strcmp(pam_hook_type, "open_session") || strcmp(pam_hook_type, "close_session"))) {
				pam_mod_type = "session";
		} else if (strcmp(pam_hook_type, "chauthtok") == 0) {
				pam_mod_type = "password";
		}

		ltable_push_str(L, "type", pam_mod_type);

		// Flags
		lua_pushstring(L, "flag");
		lua_newtable(L);
		{
			ltable_push_str_bool(L, "silent", flags & PAM_SILENT);
			if (strcmp(pam_hook_type, "authenticate")) {
				ltable_push_str_bool(L, "disallow_null_authtok", flags & PAM_DISALLOW_NULL_AUTHTOK);
			} else if (strcmp(pam_hook_type, "setcred")) {
				ltable_push_str_bool(L, "delete_cred", flags & PAM_DELETE_CRED);
				ltable_push_str_bool(L, "reinitialize_cred", flags & PAM_REINITIALIZE_CRED);
				ltable_push_str_bool(L, "refresh_cred", flags & PAM_REFRESH_CRED);
			} else if (strcmp(pam_hook_type, "chauthtok")) {
				ltable_push_str_bool(L, "change_expired_authtok", flags & PAM_CHANGE_EXPIRED_AUTHTOK);
			}
		}
		lua_settable(L, -3);

		// Args
		lua_pushstring(L, "args");
		lua_newtable(L);
		for (int i = 0; i < argc; i++) {
			lua_pushnumber(L, i+1);
			lua_pushstring(L, argv[i]);
			lua_settable(L, -3);
		}
		lua_settable(L, -3);

		// I/O functions
		ltable_push_str_func(L, "info", pam_lua_info);
		ltable_push_str_func(L, "error", pam_lua_error);
		ltable_push_str_func(L, "readline", pam_lua_readline);

		// get user function
		ltable_push_str_func(L, "get_user", pam_lua_get_user);

		// environment
		ltable_push_str_func(L, "getenv", pam_lua_getenv);
		ltable_push_str_func(L, "setenv", pam_lua_setenv);

		// item functions
		ltable_push_str_func(L, "get_item", pam_lua_get_item);
		ltable_push_str_func(L, "set_item", pam_lua_set_item);

		// ret: PAM return codes.
		// It was a pain in the ass to bind them.
		lua_pushstring(L, "ret");
		lua_newtable(L);
		{
			ltable_push_str_int(L, "success", PAM_SUCCESS);
			ltable_push_str_int(L, "open_err", PAM_OPEN_ERR);
			ltable_push_str_int(L, "symbol_err", PAM_SYMBOL_ERR);
			ltable_push_str_int(L, "service_err", PAM_SERVICE_ERR);
			ltable_push_str_int(L, "system_err", PAM_SYSTEM_ERR);
			ltable_push_str_int(L, "buf_err", PAM_BUF_ERR);
			ltable_push_str_int(L, "perm_denied", PAM_PERM_DENIED);
			ltable_push_str_int(L, "cred_insufficient", PAM_CRED_INSUFFICIENT);
			ltable_push_str_int(L, "authinfo_unavail", PAM_AUTHINFO_UNAVAIL);
			ltable_push_str_int(L, "user_unknown", PAM_USER_UNKNOWN);
			ltable_push_str_int(L, "maxtries", PAM_MAXTRIES);
			ltable_push_str_int(L, "new_authtok_reqd", PAM_NEW_AUTHTOK_REQD);
			ltable_push_str_int(L, "acct_expired", PAM_ACCT_EXPIRED);
			ltable_push_str_int(L, "session_err", PAM_SESSION_ERR);
			ltable_push_str_int(L, "cred_unavail", PAM_CRED_UNAVAIL);
			ltable_push_str_int(L, "cred_expired", PAM_CRED_EXPIRED);
			ltable_push_str_int(L, "cred_err", PAM_CRED_ERR);
			ltable_push_str_int(L, "no_module_data", PAM_NO_MODULE_DATA);
			ltable_push_str_int(L, "conv_err", PAM_CONV_ERR);
			ltable_push_str_int(L, "authtok_err", PAM_AUTHTOK_ERR);
			ltable_push_str_int(L, "authtok_recovery_err", PAM_AUTHTOK_RECOVERY_ERR);
			ltable_push_str_int(L, "authtok_lock_busy", PAM_AUTHTOK_LOCK_BUSY);
			ltable_push_str_int(L, "authtok_disable_aging", PAM_AUTHTOK_DISABLE_AGING);
			ltable_push_str_int(L, "try_again", PAM_TRY_AGAIN);
			ltable_push_str_int(L, "ignore", PAM_IGNORE);
			ltable_push_str_int(L, "abort", PAM_ABORT);
			ltable_push_str_int(L, "authtok_expired", PAM_AUTHTOK_EXPIRED);
			ltable_push_str_int(L, "module_unknown", PAM_MODULE_UNKNOWN);
			ltable_push_str_int(L, "bad_item", PAM_BAD_ITEM);
			ltable_push_str_int(L, "conv_again", PAM_CONV_AGAIN);
			ltable_push_str_int(L, "incomplete", PAM_INCOMPLETE);
		};
		lua_settable(L, -3);
	};
	lua_setglobal(L, "pam");

	// Let the magic happen.
	luaL_openlibs(L);

	int lret = luaL_dostring(L, pam_lua_bootcode);
	if (lret != 0) {
		pam_error(pamh, lua_tostring(L, -1));
		lua_close(L);
		return PAM_SERVICE_ERR;
	}

	// If the code returned a return value, use it,
	// otherwise return error.
	int ret;
	if (lua_isnumber(L, -1)) {
		ret = lua_tonumber(L, -1);
	} else {
		ret = PAM_SERVICE_ERR;
	}
	lua_pop(L, -1);

	lua_close(L);
	return ret;
}

// PAM hooks
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	return pam_lua_handler("setcred", pamh, flags, argc, argv);
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	return pam_lua_handler("authenticate", pamh, flags, argc, argv);
}

PAM_EXTERN int pam_sm_acct_mgnt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	return pam_lua_handler("acct_mgnt", pamh, flags, argc, argv);
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	return pam_lua_handler("open_session", pamh, flags, argc, argv);
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	return pam_lua_handler("close_session", pamh, flags, argc, argv);
}

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	return pam_lua_handler("chauthtok", pamh, flags, argc, argv);
}
