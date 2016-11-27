# pam_lua Makefile

# Variables
CC?=cc
BOOTCODE?=src/bootcode.lua

RESULTS= pam_lua.so src/bin2c src/bootcode.h

LUA_VER=5.1
CFLAGS+= -O2 -Isrc `pkg-config --cflags lua${LUA_VER}`
LDFLAGS= -lpam `pkg-config --libs lua${LUA_VER}`

# Rules
all: pam_lua.so

pam_lua.so: src/pam_lua.c src/bootcode.h
	${CC} -std=c99 -shared -rdynamic -fPIC ${CFLAGS} ${LDFLAGS} -o $@ src/pam_lua.c

src/bin2c: src/bin2c.c
	${CC} ${CFLAGS} -o $@ $^

src/bootcode.h: src/bin2c ${BOOTCODE}
	$^ $@ pam_lua_bootcode

# Cleanup
clean:
	rm ${RESULTS} || true
