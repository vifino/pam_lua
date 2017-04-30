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
