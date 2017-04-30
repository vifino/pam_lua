////
// Lua bindings
////

static pam_handle_t *_pamhandle;

// I/O
static int pam_lua_info(lua_State* L) {
	const char* text = luaL_checkstring(L, 1);
	lua_pushnumber(L, pamh_info(_pamhandle, text));
	return 1;
}

static int pam_lua_error(lua_State* L) {
	const char* text = luaL_checkstring(L, 1);
	lua_pushnumber(L, pamh_error(_pamhandle, text));
	return 1;
}

static int pam_lua_readline(lua_State* L) {
	int visible = lua_toboolean(L, 1);

	char* res;
	int ret;
	if (lua_isstring(L, 2)) {
		ret = pamh_readline(_pamhandle, visible, lua_tostring(L, 2), &res);
	} else {
		ret = pamh_readline(_pamhandle, visible, "", &res);
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
