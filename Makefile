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
BUILD=`echo 3`

PREFIX=/usr/local

CFLAGS+=-DBUILD=$(BUILD) -DVERSION=$(VERSION)

#dependencies:
# readline, libc-dev (un.h)

all: $(PROGNAMES)

fenris:
ragnarok:
fprints:
dress:
aegir:
nc-aegir:

debug: fenris.c fenris.h config.h ioctls.h fprints.c
	@./build-project debug

heavy: fenris.c fenris.h config.h ioctls.h fprints.c
	@./build-project heavy

prof: fenris.c fenris.h config.h ioctls.h fprints.c
	@./build-project prof

test: debug test/trivial1
	./fenris test/trivial1

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
