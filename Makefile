ls_srcs = $(shell find src -name "*.c")
ls_objs = $(ls_srcs:.c=.o)
ls_cflags = -Isrc -Ilib/lua-5.2.1/src -Ilib/libuv-node-v0.9.7/include
ls_ldflags = -lpthread -lrt -lm

liblua = lib/lua-5.2.1/src/liblua.a
libuv =  lib/libuv-node-v0.9.7/libuv.a
libs = $(liblua) $(libuv)

all: lserver

lserver: $(ls_objs) $(libs)
	gcc -o $@ $(ls_objs) $(libs) $(ls_ldflags)

echo:
	@echo $(ls_srcs)
	@echo $(ls_objs)

$(ls_objs): %.o: %.c
	gcc -g -c -o $@ $< $(ls_cflags)

$(liblua):
	$(MAKE) -C lib/lua-5.2.1/src a SYSCFLAGS="-DLUA_USE_LINUX" MYCFLAGS="-I../../../src"

$(libuv):
	$(MAKE) -C lib/libuv-node-v0.9.7

clean:
	$(MAKE) -C lib/lua-5.2.1/src clean
	$(MAKE) -C lib/libuv-node-v0.9.7 clean
	rm -f $(ls_objs) lserver
