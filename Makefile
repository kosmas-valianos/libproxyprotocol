CFLAGS := -Wall -Wextra -Wshadow -ansi -fshort-enums -fpic

all: build

build: libs_dir libs/libproxyprotocol.a libs/libproxyprotocol.so

libs_dir:
	mkdir -p libs

libs/libproxyprotocol.a: src/proxy_protocol.o
	$(AR) cr $@ $+

libs/libproxyprotocol.so: src/proxy_protocol.o
	$(CC) -shared -o $@ $+

src/%.o: %.c src/proxy_protocol.h
	$(CC) ${CFLAGS} -c -o $@ $<

tests: tests/testpp
	$<

tests/testpp: tests/test.o libs/libproxyprotocol.a
	$(CC) ${CFLAGS} -o $@ $+

clean:
	$(RM) src/*.o libs/libproxyprotocol.a libs/libproxyprotocol.so
	$(RM) tests/test.o