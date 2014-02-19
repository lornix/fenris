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
CC=gcc

PROGNAMES=fenris ragnarok fprints dress aegir nc-aegir
TOOLNAMES=getfprints fenris-bug ragsplit splitter.pl
MANFILES=$(addprefix doc/man/, $(addsuffix .1, $(PROGNAMES) $(TOOLNAMES)))
DOCFILES=$(addprefix doc/, ChangeLog LICENSE README TODO anti-fenris.txt be.txt debug-api.txt depends.txt fenris.asc other.txt reverse.txt roadmap.txt)

VERSION=0.07-m2
# FIXME:NIX add git ID here, + push count?
BUILD=3

PREFIX=/usr/local

# basic info passed to programs
CFLAGS+=-DBUILD='"$(BUILD)"' -DVERSION='"$(VERSION)"'
#
# always want these
CFLAGS+=-Wall -Wextra -Wunused
CFLAGS+=-Werror
CFLAGS+=-Wunused-macros
#
# some optimizations?
# CFLAGS+=-fomit-frame-pointer -funroll-loops -fexpensive-optimizations -ffast-math
#
CFLAGS+=-O0
# CFLAGS+=-O3
#
# Debugging?
CFLAGS+=-g3
#
# program code type debugging
# CFLAGS+=-DDEBUG=1
#
# basic libraries needed
LDFLAGS+=-ldl
LDFLAGS+=-lbfd
# LDFLAGS+=-liberty
# LDFLAGS+=-rdynamic
#
# for openSSL
CFLAGS+=-DUSE_OPENSSL=1
LDFLAGS+=-lcrypto
#
# for readline
# CFLAGS+=-DHAVE_READLINE -D__USE_TERMCAP
# LDFLAGS+=-lreadline -ltermcap
#
# link time optimizations? smaller execs!
# CFLAGS+=-flto
# LDFLAGS+=-flto
#
# extra stuff
CFLAGS+=-DLIBCSEG="0x2A"
#
# useful for figuring out what a macro ends up like
#CFLAGS+=--save-temps

#dependencies:
# readline-dev, libc-dev (un.h), openSSL-dev, binutils-dev (bfd.h),
# ncurses-dev, screen

.PHONY: all fingerprints install uninstall clean realclean

all: $(PROGNAMES)

fenris.o: fenris.c fenris.h config.h ioctls.h libdisasm/libdis.h fdebug.h hooks.h allocs.h libfnprints.h syscallnames.h
	$(CC) -c $(CFLAGS) -o $@ $<
fenris: fenris.o hooks.o allocs.o rstree.o libfnprints.o libdisasm/libdis.o libdisasm/i386.o
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) hooks.o allocs.o rstree.o libfnprints.o libdisasm/libdis.o libdisasm/i386.o

ragnarok.o: ragnarok.c config.h html.h
	$(CC) -c $(CFLAGS) -o $@ $<
ragnarok: ragnarok.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

fprints.o: fprints.c config.h libfnprints.h
	$(CC) -c $(CFLAGS) -o $@ $<
fprints: fprints.o libfnprints.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< libfnprints.o

dress.o: dress.c config.h libfnprints.h
	$(CC) -c $(CFLAGS) -o $@ $<
dress: dress.o libfnprints.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< libfnprints.o

aegir.o: aegir.c config.h fdebug.h syscallnames.h libdisasm/opcodes2/opdis.h
	$(CC) -c $(CFLAGS) -o $@ $<
aegir: aegir.o libdisasm/opcodes2/i386-dis.o libdisasm/opcodes2/opdis.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< libdisasm/opcodes2/opdis.o libdisasm/opcodes2/i386-dis.o

nc-aegir.o: nc-aegir.c config.h fdebug.h rstree.h syscallnames.h libdisasm/opcodes2/opdis.h
	$(CC) -c $(CFLAGS) -o $@ $<
nc-aegir: nc-aegir.o rstree.o libdisasm/opcodes2/i386-dis.o libdisasm/opcodes2/opdis.o
	$(CC) $(CFLAGS) $(LDFLAGS) -lncurses -o $@ $< rstree.o libdisasm/opcodes2/opdis.o libdisasm/opcodes2/i386-dis.o

# ===================== Libraries =========================

allocs.o: allocs.c allocs.h rstree.h
	$(CC) $(CFLAGS) -c -o $@ $<
hooks.o: hooks.c hooks.h config.h fenris.h fdebug.h libfnprints.h
	$(CC) $(CFLAGS) -c -o $@ $<
libfnprints.o: libfnprints.c libfnprints.h config.h
	$(CC) $(CFLAGS) -c -o $@ $<
rstree.o: rstree.c rstree.h
	$(CC) $(CFLAGS) -c -o $@ $<
libdisasm/i386.o: libdisasm/i386.c libdisasm/i386.h libdisasm/bastard.h libdisasm/extension.h libdisasm/i386-opcodes.h
	$(CC) $(CFLAGS) -c -o $@ $<
libdisasm/libdis.o: libdisasm/libdis.c libdisasm/bastard.h libdisasm/extension.h libdisasm/libdis.h libdisasm/i386.h libdisasm/i386-opcodes.h
	$(CC) $(CFLAGS) -c -o $@ $<
libdisasm/opcodes2/i386-dis.o: libdisasm/opcodes2/i386-dis.c libdisasm/opcodes2/dis-asm.h libdisasm/opcodes2/bfd.h
	$(CC) $(CFLAGS) -c -o $@ $<
libdisasm/opcodes2/opdis.o: libdisasm/opcodes2/opdis.c libdisasm/opcodes2/dis-asm.h libdisasm/opcodes2/bfd.h libdisasm/opcodes2/opdis.h
	$(CC) $(CFLAGS) -c -o $@ $<

fingerprints: fprints
	@if [ ! -f fnprints.dat ]; then touch fnprints.dat; fi
	@echo "[*] Updating libc fingerprint database (this will take a while)..."
	@./getfprints --quiet --force
	@echo "[*] Sorting fingerprints..."
	@BEFORE=`wc -l < fnprints.dat`; \
	       sort fnprints.dat fnprints.new | uniq > .tmp; \
	       mv .tmp fnprints.dat; \
	       rm -f fnprints.new; \
	       AFTER=`wc -l < fnprints.dat`; \
	       CHANGE=`expr $${AFTER} - $${BEFORE}`; \
	       echo "You have $${AFTER} fingerprints, a change of $${CHANGE}"

# debug: fenris.c fenris.h config.h ioctls.h fprints.c
#         @./build-project debug

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

syscallnames.h:
	@echo Creating syscallnames.h
	@# dummy up the syscallnames.h file
	@echo "#include <x86_64-linux-gnu/asm/unistd.h>" > syscallnames.h
	@echo "#include <x86_64-linux-gnu/asm/unistd_32.h>" > syscallnames.h
	@# arm (tinker)
	@#     /usr/include/asm-generic/unistd.h
	@# i386
	@#     /usr/include/asm-generic/unistd.h ???
	@# x86_64 (xenon)
	@#     /usr/include/x86_64-linux-gnu/asm/unistd.h
	@#     /usr/include/x86_64-linux-gnu/asm/unistd_32.h
	@#     /usr/include/x86_64-linux-gnu/asm/unistd_64.h
	@#
	@# parsed with:
	@# awk '/#define __NR_/{print "\"" $2"\", " $3 ","}' <file> |
	@#     sed "s/__NR_//' > syscalls_list.h

uninstall:
	@rm -rf $(PREFIX)/share/doc/fenris
	@rm -rf $(PREFIX)/etc/fenris
	@rm -f $(addprefix $(PREFIX)/bin/, $(PROGNAMES) $(TOOLNAMES))
	@rm -f $(addsuffix .1, $(addprefix $(PREFIX)/share/man/man1/, $(PROGNAMES) $(TOOLNAMES)))

clean:
	@echo Removing object files, programs
	@rm -f $(PROGNAMES)
	@rm -f *.o *~
	@rm -f rstree.o allocs.o libfnprints.o hooks.o
	@rm -f libdisasm/i386.o libdisasm/libdis.o libdisasm/opcodes2/i386-dis.o libdisasm/opcodes2/opdis.o
	@rm -f syscallnames.h

realclean: clean
	@echo Removing fingerprint data
	@rm -f fnprints.dat fnprints.new

