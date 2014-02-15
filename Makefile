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

all: fenris

fenris: fenris.c fenris.h config.h ioctls.h fprints.c
	@./build-project

minimal: fenris.c fenris.h config.h ioctls.h fprints.c
	@./build-project minimal

debug: fenris.c fenris.h config.h ioctls.h fprints.c
	@./build-project debug

heavy: fenris.c fenris.h config.h ioctls.h fprints.c
	@./build-project heavy

prof: fenris.c fenris.h config.h ioctls.h fprints.c
	@./build-project prof

test: debug test/trivial1
	./fenris test/trivial1

install: all
	-mkdir -p /usr/doc/fenris/
	-cp -f doc/* /usr/doc/fenris/
	cp -f doc/man/* /usr/man/man1
	cp -f fnprints.dat /etc/
	cp -f fenris /usr/bin/
	cp -f fprints /usr/bin/
	cp -f getfprints /usr/bin/
	cp -f ragnarok /usr/bin/
	cp -f fenris-bug /usr/bin/
	cp -f ragsplit /usr/bin/
	cp -f dress /usr/bin/
	cp -f aegir /usr/bin/
	cp -f nc-aegir /usr/bin/ || true
	cp -f splitter.pl /usr/bin/

uninstall:
	rm -rf /usr/doc/fenris
	rm -f /etc/fnprints.dat /usr/bin/fenris /usr/bin/fprints /usr/bin/getfprints /usr/bin/ragnarok /usr/bin/fenris-bug /usr/bin/ragsplit /usr/bin/splitter.pl /usr/bin/dress /usr/bin/aegir /usr/bin/nc-aegir

clean:
	@./build-project clean
	@echo "Our bugs run faster."
