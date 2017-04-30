// pam_lua: Scriptable PAM module using Lua
// Author: Adrian "vifino" Pistol

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

// Lua 'bootcode'
#include <bootcode.h>
// Other parts of our saucecode
#include <pam_compat.h> // our pam compat.
#include <pam_helpers.c> // little convenience helpers for pam

#include <helpers.c> // convenience helpers

// Lua stuff
#include <lua_helpers.c>
#include <lua_bindings.c>

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
			ltable_push_str_int(L, "bad_item", PAMC_BAD_ITEM);
			ltable_push_str_int(L, "incomplete", PAMC_INCOMPLETE);

			// OS-specific/maybeithasthis stuff
#ifdef PAM_CONV_AGAIN
			ltable_push_str_int(L, "conv_again", PAM_CONV_AGAIN);
#endif
		};
		lua_settable(L, -3);
	};
	lua_setglobal(L, "pam");

	// Let the magic happen.
	luaL_openlibs(L);

	int lret = luaL_dostring(L, pam_lua_bootcode);
	if (lret != 0) {
		pamh_error(pamh, lua_tostring(L, -1));
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
