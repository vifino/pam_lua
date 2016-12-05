# pam_lua Makefile

# Variables
CC?=cc
BOOTCODE?=src/bootcode.lua

RESULTS= pam_lua.so src/bin2c src/bootcode.h

# The version of Lua we are compiling and linking against. 5.1 for lua5.1, jit for luajit, etc..
LUA_VER=5.1

CFLAGS+= -O2 -Isrc `pkg-config --cflags lua${LUA_VER}`
LDFLAGS= -lpam `pkg-config --libs lua${LUA_VER}`

all: pam_lua.so

# Flag rules
debug: CFLAGS+= -ggdb
debug: pam_lua.so

# Rules
pam_lua.so: src/pam_lua.c src/bootcode.h
	${CC} -pedantic -std=c99 -shared -rdynamic -fPIC ${CFLAGS} ${LDFLAGS} -o $@ src/pam_lua.c

src/bin2c: src/bin2c.c
	${CC} ${CFLAGS} -o $@ $^

src/bootcode.h: src/bin2c ${BOOTCODE}
	$^ $@ pam_lua_bootcode

# Cleanup
clean:
	rm ${RESULTS} || true
