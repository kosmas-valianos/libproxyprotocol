CFLAGS := -Wall -Wextra -Wshadow -ansi -fshort-enums -fpic

all: build

build: libs_dir libs/libpp.so

libs_dir:
	mkdir -p libs

libs/libpp.so: src/proxy_protocol.o
	$(CC) -shared -o $@ $+

src/%.o: %.c src/proxy_protocol.h
	$(CC) ${CFLAGS} -c -o $@ $<

tests: tests/testlibpp
	LD_LIBRARY_PATH=libs/ $<

tests/testlibpp: tests/test.o libs/libpp.so
	$(CC) -Llibs/ ${CFLAGS} -o $@ $< -lpp

clean:
	$(RM) src/*.o libs/libpp.so
	$(RM) tests/test.o