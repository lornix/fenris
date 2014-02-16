#
#  fenris - program execution path analysis tool
#  ---------------------------------------------
#
#  Copyright (C) 2001, 2002 by Bindview Corporation
#  Portions Copyright (C) 2001, 2002 by their respective contributors
#  Developed and maintained by Michal Zalewski <lcamtuf@coredump.cx>
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#

PROGNAMES=fenris ragnarok fprints dress aegir nc-aegir
TOOLNAMES=getfprints fenris-bug ragsplit splitter.pl
MANFILES=$(addprefix doc/man/, $(addsuffix .1, $(PROGNAMES) $(TOOLNAMES)))
DOCFILES=$(addprefix doc/, ChangeLog LICENSE README TODO anti-fenris.txt be.txt debug-api.txt depends.txt fenris.asc other.txt reverse.txt roadmap.txt)

VERSION=0.07-m2
# FIXME: add git ID here, + push count?
BUILD=`echo 3`

PREFIX=/usr/local

# basic info passed to programs
CFLAGS+=-DBUILD=$(BUILD) -DVERSION=$(VERSION)
#
# always want these
CFLAGS+=-Wall -Wextra -Wunused
#
# some optimizations?
# CFLAGS+=-fomit-frame-pointer -funroll-loops -fexpensive-optimizations -ffast-math
#
CFLAGS+=-O0
# CFLAGS+=-O3
#
# CFLAGS+=-Werror
#
# Debugging?
CFLAGS+=-g3
#
# program code type debugging
# CFLAGS+=-DDEBUG=1
#
# big time debugging?
# CFLAGS+=-DHEAVY_DEBUG=1
#
# profiling?
# CFLAGS+=-fno-inline -pg -DPROFILE=1 -DDEBUG=1
#
# basic libraries needed
# LDFLAGS+=-ldl -lbfd -liberty
# LDFLAGS+=-rdynamic
#
# for openSSL
# CFLAGS+=-DUSE_OPENSSL=1
# LDFLAGS+=-lcrypto
#
# for readline
# CFLAGS+=-DHAVE_READLINE -D__USE_TERMCAP
# LDFLAGS+=-lreadline -ltermcap
#
# for ncurses
# CFLAGS+=
# LDFLAGS+=-lncurses
#
# link time optimizations? smaller execs!
# CFLAGS+=-flto
# LDFLAGS+=-flto
#
# extra stuff
CFLAGS+=-DLIBCSEG=0x00 

#dependencies:
# readline-dev, libc-dev (un.h), openSSL-dev, binutils-dev (bfd.h),
# ncurses-dev, screen

all: $(PROGNAMES)

fenris: fenris.c fenris.h i386.o libdis.o rstree.o allocs.o libfnprints.o hooks.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

ragnarok: ragnarok.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

fprints: fprints.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

dress: dress.c libfnprints.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

aegir: aegir.c libfnprints.o i386-dis.o opdis.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

nc-aegir: nc-aegir.c libfnprints.o i386-dis.o opdis.o rstree.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

libdisasm/i386.so: libdisasm/i386.c
	$(CC) -c $(CFLAGS) -o $@ $<

libdisasm/libdis.so: libdisasm/libdis.c
	$(CC) -c $(CFLAGS) -o $@ $<

libdisasm/opcodes/i386-dis.so: libdisasm/opcodes/i386-dis.c
	$(CC) -c $(CFLAGS) -o $@ $<

libdisasm/opcodes/opdis.so: libdisasm/opcodes/opdis.c
	$(CC) -c $(CFLAGS) -o $@ $<

rstree.so: rstree.c
	$(CC) -c $(CFLAGS) -o $@ $<

allocs.so: allocs.c
	$(CC) -c $(CFLAGS) -o $@ $<

libfnprints.so: libfnprints.c
	$(CC) -c $(CFLAGS) -o $@ $<

hooks.so: hooks.c
	$(CC) -c $(CFLAGS) -o $@ $<

fingerprints:
	@touch fnprints.dat
	@echo "[*] Updating libc fingerprints database (this will take a while)..."
	@-NOBANNER=1 ./getfprints
	@echo "[*] Sorting your fingerprints..."
	@sort fnprints.dat NEW-fnprints.dat | uniq > .tmp
	@mv .tmp fnprints.dat
	@rm -f NEW-fnprints.dat
	@echo "You have `wc -l < fnprints.dat` fingerprints"

# debug: fenris.c fenris.h config.h ioctls.h fprints.c
#         @./build-project debug

# heavy: fenris.c fenris.h config.h ioctls.h fprints.c
#         @./build-project heavy

# prof: fenris.c fenris.h config.h ioctls.h fprints.c
#         @./build-project prof

# test: debug test/trivial1
#         ./fenris test/trivial1

install: all
	install --directory $(PREFIX)/etc/fenris/
	install --directory $(PREFIX)/share/doc/fenris/
	install --directory $(PREFIX)/share/man/man1/
	install --directory $(PREFIX)/bin/
	install --mode 644 fnprints.dat $(PREFIX)/etc/fenris/
	install --mode 644 $(DOCFILES) $(PREFIX)/share/doc/fenris/
	install --mode 644 $(MANFILES) $(PREFIX)/share/man/man1/
	install --mode 755 $(PROGNAMES) $(TOOLNAMES) $(PREFIX)/bin/

gather_syscalls:
	# arm (tinker)
	#     /usr/include/asm-generic/unistd.h
	# i386
	#     /usr/include/asm-generic/unistd.h ???
	# x86_64 (xenon)
	#     /usr/include/x86_64-linux-gnu/asm/unistd_32.h
	#     /usr/include/x86_64-linux-gnu/asm/unistd_64.h
	#
	# parsed with:
	# awk '/#define __NR_/{print "\"" $2"\", " $3 ","}' <file> |
	#     sed "s/__NR_//' > syscalls_list.h

uninstall:
	rm -rf $(PREFIX)/share/doc/fenris
	rm -rf $(PREFIX)/etc/fenris
	rm -f $(addprefix $(PREFIX)/bin/, $(PROGNAMES) $(TOOLNAMES))
	rm -f $(addsuffix .1, $(addprefix $(PREFIX)/share/man/man1/, $(PROGNAMES) $(TOOLNAMES)))

clean:
	rm -f $(PROGNAMES) $(TOOLNAMES)
	rm -f *.o *~
