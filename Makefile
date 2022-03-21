#
# libproxyprotocol is an ANSI C library to parse and create PROXY protocol v1 and v2 headers
# Copyright (C) 2022  Kosmas Valianos (kosmas.valianos@gmail.com)
#
# The libproxyprotocol library is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# The libproxyprotocol library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#

CFLAGS := -Wall -Wextra -Wshadow -Wimplicit-fallthrough=0 -ansi -fshort-enums -fpic

all: build

build: libs_dir libs/libproxyprotocol.so

libs_dir:
	mkdir -p libs

libs/libproxyprotocol.so: src/proxy_protocol.o
	$(CC) -shared -o $@ $+

src/%.o: %.c src/proxy_protocol.h
	$(CC) ${CFLAGS} -c -o $@ $<

tests: tests/test_libproxyprotocol
	LD_LIBRARY_PATH=libs/ $<

tests/test_libproxyprotocol: tests/test.o libs/libproxyprotocol.so
	$(CC) -Llibs/ ${CFLAGS} -o $@ $< -lproxyprotocol

clean:
	$(RM) src/*.o libs/libproxyprotocol.so
	$(RM) tests/*.o tests/test_libproxyprotocol
