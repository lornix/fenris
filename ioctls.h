/*
    fenris - program execution path analysis tool
    ---------------------------------------------

    Copyright (C) 2001, 2002 by Bindview Corporation
    Portions copyright (C) 2001, 2002 by their respective contributors
    Developed and maintained by Michal Zalewski <lcamtuf@coredump.cx>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

    IOCTLs list. Linux does not have a single and clean location to look
    for them, so we will carry the list with us. I added socketcall
    parameters here as well - we have them in linux/net.h, but including
    this file causes some redefinitions and such.

 */

#ifndef _HAVE_IOCTLS_H
#define _HAVE_IOCTLS_H 1

struct ioctl_data {
    unsigned int n;
    char* name;
};

struct ioctl_data ioctls[] = {
    { 0x890B, "SIOCADDRT" },              { 0x890C, "SIOCDELRT" },
    { 0x890D, "SIOCRTMSG" },              { 0x8910, "SIOCGIFNAME" },
    { 0x8911, "SIOCSIFLINK" },            { 0x8912, "SIOCGIFCONF" },
    { 0x8913, "SIOCGIFFLAGS" },           { 0x8914, "SIOCSIFFLAGS" },
    { 0x8915, "SIOCGIFADDR" },            { 0x8916, "SIOCSIFADDR" },
    { 0x8917, "SIOCGIFDSTADDR" },         { 0x8918, "SIOCSIFDSTADDR" },
    { 0x8919, "SIOCGIFBRDADDR" },         { 0x891a, "SIOCSIFBRDADDR" },
    { 0x891b, "SIOCGIFNETMASK" },         { 0x891c, "SIOCSIFNETMASK" },
    { 0x891d, "SIOCGIFMETRIC" },          { 0x891e, "SIOCSIFMETRIC" },
    { 0x891f, "SIOCGIFMEM" },             { 0x8920, "SIOCSIFMEM" },
    { 0x8921, "SIOCGIFMTU" },             { 0x8922, "SIOCSIFMTU" },
    { 0x8924, "SIOCSIFHWADDR" },          { 0x8925, "SIOCGIFENCAP" },
    { 0x8926, "SIOCSIFENCAP" },           { 0x8927, "SIOCGIFHWADDR" },
    { 0x8929, "SIOCGIFSLAVE" },           { 0x8930, "SIOCSIFSLAVE" },
    { 0x8931, "SIOCADDMULTI" },           { 0x8932, "SIOCDELMULTI" },
    { 0x8933, "SIOCGIFINDEX" },           { 0x8934, "SIOCSIFPFLAGS" },
    { 0x8935, "SIOCGIFPFLAGS" },          { 0x8936, "SIOCDIFADDR" },
    { 0x8937, "SIOCSIFHWBROADCAST" },     { 0x8938, "SIOCGIFCOUNT" },
    { 0x8940, "SIOCGIFBR" },              { 0x8941, "SIOCSIFBR" },
    { 0x8942, "SIOCGIFTXQLEN" },          { 0x8943, "SIOCSIFTXQLEN" },
    { 0x8953, "SIOCDARP" },               { 0x8954, "SIOCGARP" },
    { 0x8955, "SIOCSARP" },               { 0x8960, "SIOCDRARP" },
    { 0x8961, "SIOCGRARP" },              { 0x8962, "SIOCSRARP" },
    { 0x8970, "SIOCGIFMAP" },             { 0x8971, "SIOCSIFMAP" },
    { 0x8980, "SIOCADDDLCI" },            { 0x8981, "SIOCDELDLCI" },
    { 0x89F0, "SIOCDEVPRIVATE1" },        { 0x89F1, "SIOCDEVPRIVATE2" },
    { 0x89F2, "SIOCDEVPRIVATE3" },        { 0x89F3, "SIOCDEVPRIVATE4" },
    { 0x89F4, "SIOCDEVPRIVATE5" },        { 0x89F5, "SIOCDEVPRIVATE6" },
    { 0x89F6, "SIOCDEVPRIVATE7" },        { 0x89F7, "SIOCDEVPRIVATE8" },
    { 0x89F8, "SIOCDEVPRIVATE9" },        { 0x89F9, "SIOCDEVPRIVATE10" },
    { 0x89FA, "SIOCDEVPRIVATE11" },       { 0x89FB, "SIOCDEVPRIVATE12" },
    { 0x89FC, "SIOCDEVPRIVATE13" },       { 0x89FD, "SIOCDEVPRIVATE14" },
    { 0x89FE, "SIOCDEVPRIVATE15" },       { 0x89FF, "SIOCDEVPRIVATE16" },
    { 0x89E0, "SIOCPROTOPRIVATE1" },      { 0x89E1, "SIOCPROTOPRIVATE2" },
    { 0x89E2, "SIOCPROTOPRIVATE3" },      { 0x89E3, "SIOCPROTOPRIVATE4" },
    { 0x89E4, "SIOCPROTOPRIVATE5" },      { 0x89E5, "SIOCPROTOPRIVATE6" },
    { 0x89E6, "SIOCPROTOPRIVATE7" },      { 0x89E7, "SIOCPROTOPRIVATE8" },
    { 0x89E8, "SIOCPROTOPRIVATE9" },      { 0x89E9, "SIOCPROTOPRIVATE10" },
    { 0x89EA, "SIOCPROTOPRIVATE11" },     { 0x89EB, "SIOCPROTOPRIVATE12" },
    { 0x89EC, "SIOCPROTOPRIVATE13" },     { 0x89ED, "SIOCPROTOPRIVATE14" },
    { 0x89EE, "SIOCPROTOPRIVATE15" },     { 0x89EF, "SIOCPROTOPRIVATE16" },
    { 0x5401, "TCGETS" },                 { 0x5402, "TCSETS" },
    { 0x5403, "TCSETSW" },                { 0x5404, "TCSETSF" },
    { 0x5405, "TCGETA" },                 { 0x5406, "TCSETA" },
    { 0x5407, "TCSETAW" },                { 0x5408, "TCSETAF" },
    { 0x5409, "TCSBRK" },                 { 0x540A, "TCXONC" },
    { 0x540B, "TCFLSH" },                 { 0x540C, "TIOCEXCL" },
    { 0x540D, "TIOCNXCL" },               { 0x540E, "TIOCSCTTY" },
    { 0x540F, "TIOCGPGRP" },              { 0x5410, "TIOCSPGRP" },
    { 0x5411, "TIOCOUTQ" },               { 0x5412, "TIOCSTI" },
    { 0x5413, "TIOCGWINSZ" },             { 0x5414, "TIOCSWINSZ" },
    { 0x5415, "TIOCMGET" },               { 0x5416, "TIOCMBIS" },
    { 0x5417, "TIOCMBIC" },               { 0x5418, "TIOCMSET" },
    { 0x5419, "TIOCGSOFTCAR" },           { 0x541A, "TIOCSSOFTCAR" },
    { 0x541B, "FIONREAD" },               { 0x541C, "TIOCLINUX" },
    { 0x541D, "TIOCCONS" },               { 0x541E, "TIOCGSERIAL" },
    { 0x541F, "TIOCSSERIAL" },            { 0x5420, "TIOCPKT" },
    { 0x5421, "FIONBIO" },                { 0x5422, "TIOCNOTTY" },
    { 0x5423, "TIOCSETD" },               { 0x5424, "TIOCGETD" },
    { 0x5425, "TCSBRKP" },                { 0x5426, "TIOCTTYGSTRUCT" },
    { 0x5427, "TIOCSBRK" },               { 0x5428, "TIOCCBRK" },
    { 0x5429, "TIOCGSID" },               { 0x5450, "FIONCLEX" },
    { 0x5451, "FIOCLEX" },                { 0x5452, "FIOASYNC" },
    { 0x5453, "TIOCSERCONFIG" },          { 0x5454, "TIOCSERGWILD" },
    { 0x5455, "TIOCSERSWILD" },           { 0x5456, "TIOCGLCKTRMIOS" },
    { 0x5457, "TIOCSLCKTRMIOS" },         { 0x5458, "TIOCSERGSTRUCT" },
    { 0x5459, "TIOCSERGETLSR" },          { 0x545A, "TIOCSERGETMULTI" },
    { 0x545B, "TIOCSERSETMULTI" },        { 0x545C, "TIOCMIWAIT" },
    { 0x545D, "TIOCGICOUNT" },            { 0x545E, "TIOCGHAYESESP" },
    { 0x545F, "TIOCSHAYESESP" },
};

// linux/net.h

#define SYS_SOCKET      1               /* sys_socket(2)                */
#define SYS_BIND        2               /* sys_bind(2)                  */
#define SYS_CONNECT     3               /* sys_connect(2)               */
#define SYS_LISTEN      4               /* sys_listen(2)                */
#define SYS_ACCEPT      5               /* sys_accept(2)                */
#define SYS_GETSOCKNAME 6               /* sys_getsockname(2)           */
#define SYS_GETPEERNAME 7               /* sys_getpeername(2)           */
#define SYS_SOCKETPAIR  8               /* sys_socketpair(2)            */
#define SYS_SEND        9               /* sys_send(2)                  */
#define SYS_RECV        10              /* sys_recv(2)                  */
#define SYS_SENDTO      11              /* sys_sendto(2)                */
#define SYS_RECVFROM    12              /* sys_recvfrom(2)              */
#define SYS_SHUTDOWN    13              /* sys_shutdown(2)              */
#define SYS_SETSOCKOPT  14              /* sys_setsockopt(2)            */
#define SYS_GETSOCKOPT  15              /* sys_getsockopt(2)            */
#define SYS_SENDMSG     16              /* sys_sendmsg(2)               */
#define SYS_RECVMSG     17              /* sys_recvmsg(2)               */

#endif /* not _HAVE_IOCTLS_H */
