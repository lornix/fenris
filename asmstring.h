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

   This code comes from Linux kernel 2.2.x and has been slightly altered
   to fit our needs. I do not use the one that can be found in
   /usr/include/asm because I had some reports that not all systems
   have it working.

   Most of this code comes probably from Petko Manolov, Alberto Vignani,
   Davide Parodi or Linus Torvalds.

 */

#ifndef _I386_STRING_H_
#define _I386_STRING_H_

// Just in case...
#undef strcpy
#undef strncpy
#undef memset
#undef strcat
#undef strncat
#undef strcmp
#undef strncmp
#undef strchr
#undef strrchr
#undef strlen
#undef __memcpy
#undef __constant_memcpy
#undef memmove
#undef memchr
#undef __memset_generic
#undef __constant_c_memset
#undef strnlen
#undef strstr
#undef __constant_c_and_count_memset
#undef memscan


#define __HAVE_ARCH_STRCPY
inline char * strcpy(char * dest,const char *src)
{
    int d0, d1, d2;
    __asm__ __volatile__(
            "1:\tlodsb\n\t"
            "stosb\n\t"
            "testb %%al,%%al\n\t"
            "jne 1b"
            : "=&S" (d0), "=&D" (d1), "=&a" (d2)
            :"0" (src),"1" (dest) : "memory");
    return dest;
}

#define __HAVE_ARCH_STRNCPY
inline char * strncpy(char * dest,const char *src,size_t count)
{
    int d0, d1, d2, d3;
    __asm__ __volatile__(
            "1:\tdecl %2\n\t"
            "js 2f\n\t"
            "lodsb\n\t"
            "stosb\n\t"
            "testb %%al,%%al\n\t"
            "jne 1b\n\t"
            "rep\n\t"
            "stosb\n"
            "2:"
            : "=&S" (d0), "=&D" (d1), "=&c" (d2), "=&a" (d3)
            :"0" (src),"1" (dest),"2" (count) : "memory");
    return dest;
}

#define __HAVE_ARCH_STRCAT
inline char * strcat(char * dest,const char * src)
{
    int d0, d1, d2, d3;
    __asm__ __volatile__(
            "repne\n\t"
            "scasb\n\t"
            "decl %1\n"
            "1:\tlodsb\n\t"
            "stosb\n\t"
            "testb %%al,%%al\n\t"
            "jne 1b"
            : "=&S" (d0), "=&D" (d1), "=&a" (d2), "=&c" (d3)
            : "0" (src), "1" (dest), "2" (0), "3" (0xffffffff):"memory");
    return dest;
}

#define __HAVE_ARCH_STRNCAT
inline char * strncat(char * dest,const char * src,size_t count)
{
    int d0, d1, d2, d3;
    __asm__ __volatile__(
            "repne\n\t"
            "scasb\n\t"
            "decl %1\n\t"
            "movl %8,%3\n"
            "1:\tdecl %3\n\t"
            "js 2f\n\t"
            "lodsb\n\t"
            "stosb\n\t"
            "testb %%al,%%al\n\t"
            "jne 1b\n"
            "2:\txorl %2,%2\n\t"
            "stosb"
            : "=&S" (d0), "=&D" (d1), "=&a" (d2), "=&c" (d3)
            : "0" (src),"1" (dest),"2" (0),"3" (0xffffffff), "g" (count)
            : "memory");
    return dest;
}

#define __HAVE_ARCH_STRCMP
inline int strcmp(const char * cs,const char * ct)
{
    int d0, d1;
    register int __res;
    __asm__ __volatile__(
            "1:\tlodsb\n\t"
            "scasb\n\t"
            "jne 2f\n\t"
            "testb %%al,%%al\n\t"
            "jne 1b\n\t"
            "xorl %%eax,%%eax\n\t"
            "jmp 3f\n"
            "2:\tsbbl %%eax,%%eax\n\t"
            "orb $1,%%al\n"
            "3:"
            :"=a" (__res), "=&S" (d0), "=&D" (d1)
            :"1" (cs),"2" (ct));
    return __res;
}

#define __HAVE_ARCH_STRNCMP
inline int strncmp(const char * cs,const char * ct,size_t count)
{
    register int __res;
    int d0, d1, d2;
    __asm__ __volatile__(
            "1:\tdecl %3\n\t"
            "js 2f\n\t"
            "lodsb\n\t"
            "scasb\n\t"
            "jne 3f\n\t"
            "testb %%al,%%al\n\t"
            "jne 1b\n"
            "2:\txorl %%eax,%%eax\n\t"
            "jmp 4f\n"
            "3:\tsbbl %%eax,%%eax\n\t"
            "orb $1,%%al\n"
            "4:"
            :"=a" (__res), "=&S" (d0), "=&D" (d1), "=&c" (d2)
            :"1" (cs),"2" (ct),"3" (count));
    return __res;
}

#define __HAVE_ARCH_STRCHR
char * strchr(const char * s, int c)
{
    int d0;
    register char * __res;
    __asm__ __volatile__(
            "movb %%al,%%ah\n"
            "1:\tlodsb\n\t"
            "cmpb %%ah,%%al\n\t"
            "je 2f\n\t"
            "testb %%al,%%al\n\t"
            "jne 1b\n\t"
            "movl $1,%1\n"
            "2:\tmovl %1,%0\n\t"
            "decl %0"
            :"=a" (__res), "=&S" (d0) : "1" (s),"0" (c));
    return __res;
}

#define __HAVE_ARCH_STRRCHR
inline char * strrchr(const char * s, int c)
{
    int d0, d1;
    register char * __res;
    __asm__ __volatile__(
            "movb %%al,%%ah\n"
            "1:\tlodsb\n\t"
            "cmpb %%ah,%%al\n\t"
            "jne 2f\n\t"
            "leal -1(%%esi),%0\n"
            "2:\ttestb %%al,%%al\n\t"
            "jne 1b"
            :"=g" (__res), "=&S" (d0), "=&a" (d1) :"0" (0),"1" (s),"2" (c));
    return __res;
}

#define __HAVE_ARCH_STRLEN
inline size_t strlen(const char * s)
{
    int d0;
    register int __res;
    __asm__ __volatile__(
            "repne\n\t"
            "scasb\n\t"
            "notl %0\n\t"
            "decl %0"
            :"=c" (__res), "=&D" (d0) :"1" (s),"a" (0), "0" (0xffffffff));
    return __res;
}

inline void * __memcpy(void * to, const void * from, size_t n)
{
    int d0, d1, d2;
    __asm__ __volatile__(
            "rep ; movsl\n\t"
            "testb $2,%b4\n\t"
            "je 1f\n\t"
            "movsw\n"
            "1:\ttestb $1,%b4\n\t"
            "je 2f\n\t"
            "movsb\n"
            "2:"
            : "=&c" (d0), "=&D" (d1), "=&S" (d2)
            :"0" (n/4), "q" (n),"1" ((long) to),"2" ((long) from)
            : "memory");
    return (to);
}

/*
 * This looks horribly ugly, but the compiler can optimize it totally,
 * as the count is constant.
 */
inline void * __constant_memcpy(void * to, const void * from, size_t n)
{
    switch (n) {
        case 0:
            return to;
        case 1:
            *(unsigned char *)to = *(const unsigned char *)from;
            return to;
        case 2:
            *(unsigned short *)to = *(const unsigned short *)from;
            return to;
        case 3:
            *(unsigned short *)to = *(const unsigned short *)from;
            *(2+(unsigned char *)to) = *(2+(const unsigned char *)from);
            return to;
        case 4:
            *(unsigned long *)to = *(const unsigned long *)from;
            return to;
        case 6: /* for Ethernet addresses */
            *(unsigned long *)to = *(const unsigned long *)from;
            *(2+(unsigned short *)to) = *(2+(const unsigned short *)from);
            return to;
        case 8:
            *(unsigned long *)to = *(const unsigned long *)from;
            *(1+(unsigned long *)to) = *(1+(const unsigned long *)from);
            return to;
        case 12:
            *(unsigned long *)to = *(const unsigned long *)from;
            *(1+(unsigned long *)to) = *(1+(const unsigned long *)from);
            *(2+(unsigned long *)to) = *(2+(const unsigned long *)from);
            return to;
        case 16:
            *(unsigned long *)to = *(const unsigned long *)from;
            *(1+(unsigned long *)to) = *(1+(const unsigned long *)from);
            *(2+(unsigned long *)to) = *(2+(const unsigned long *)from);
            *(3+(unsigned long *)to) = *(3+(const unsigned long *)from);
            return to;
        case 20:
            *(unsigned long *)to = *(const unsigned long *)from;
            *(1+(unsigned long *)to) = *(1+(const unsigned long *)from);
            *(2+(unsigned long *)to) = *(2+(const unsigned long *)from);
            *(3+(unsigned long *)to) = *(3+(const unsigned long *)from);
            *(4+(unsigned long *)to) = *(4+(const unsigned long *)from);
            return to;
    }
#define COMMON1(x) \
    __asm__ __volatile__( \
            "rep ; movsl" \
            x \
            : "=&c" (d0), "=&D" (d1), "=&S" (d2) \
            : "0" (n/4),"1" ((long) to),"2" ((long) from) \
            : "memory");
    {
        int d0, d1, d2;
        switch (n % 4) {
            case 0: COMMON1(""); return to;
            case 1: COMMON1("\n\tmovsb"); return to;
            case 2: COMMON1("\n\tmovsw"); return to;
            default: COMMON1("\n\tmovsw\n\tmovsb"); return to;
        }
    }

#undef COMMON1
}

#define __HAVE_ARCH_MEMCPY

#define memcpy(t, f, n) \
    (__builtin_constant_p(n) ? \
     __constant_memcpy((t),(f),(n)) : \
     __memcpy((t),(f),(n)))

extern void __struct_cpy_bug (void);

#define struct_cpy(x,y) \
    ({ \
     if (sizeof(*(x)) != sizeof(*(y))) \
     __struct_cpy_bug; \
     memcpy(x, y, sizeof(*(x))); \
     })

#define __HAVE_ARCH_MEMMOVE
inline void * memmove(void * dest,const void * src, size_t n)
{
    int d0, d1, d2;
    if (dest<src)
        __asm__ __volatile__(
                "rep\n\t"
                "movsb"
                : "=&c" (d0), "=&S" (d1), "=&D" (d2)
                :"0" (n),"1" (src),"2" (dest)
                : "memory");
    else
        __asm__ __volatile__(
                "std\n\t"
                "rep\n\t"
                "movsb\n\t"
                "cld"
                : "=&c" (d0), "=&S" (d1), "=&D" (d2)
                :"0" (n),
                "1" (n-1+(const char *)src),
                "2" (n-1+(char *)dest)
                :"memory");
    return dest;
}

#define memcmp __builtin_memcmp

#define __HAVE_ARCH_MEMCHR
void * memchr(const void * cs,int c,size_t count)
{
    int d0;
    register void * __res;
    if (!count)
        return NULL;
    __asm__ __volatile__(
            "repne\n\t"
            "scasb\n\t"
            "je 1f\n\t"
            "movl $1,%0\n"
            "1:\tdecl %0"
            :"=D" (__res), "=&c" (d0) : "a" (c),"0" (cs),"1" (count));
    return __res;
}

inline void * __memset_generic(void * s, char c,size_t count)
{
    int d0, d1;
    __asm__ __volatile__(
            "rep\n\t"
            "stosb"
            : "=&c" (d0), "=&D" (d1)
            :"a" (c),"1" (s),"0" (count)
            :"memory");
    return s;
}

/* we might want to write optimized versions of these later */
#define __constant_count_memset(s,c,count) __memset_generic((s),(c),(count))

inline void * __constant_c_memset(void * s, unsigned long c, size_t count)
{
    int d0, d1;
    __asm__ __volatile__(
            "rep ; stosl\n\t"
            "testb $2,%b3\n\t"
            "je 1f\n\t"
            "stosw\n"
            "1:\ttestb $1,%b3\n\t"
            "je 2f\n\t"
            "stosb\n"
            "2:"
            : "=&c" (d0), "=&D" (d1)
            :"a" (c), "q" (count), "0" (count/4), "1" ((long) s)
            :"memory");
    return (s);
}

#define __HAVE_ARCH_STRNLEN
inline size_t strnlen(const char * s, size_t count)
{
    int d0;
    register int __res;
    __asm__ __volatile__(
            "movl %2,%0\n\t"
            "jmp 2f\n"
            "1:\tcmpb $0,(%0)\n\t"
            "je 3f\n\t"
            "incl %0\n"
            "2:\tdecl %1\n\t"
            "cmpl $-1,%1\n\t"
            "jne 1b\n"
            "3:\tsubl %2,%0"
            :"=a" (__res), "=&d" (d0)
            :"c" (s),"1" (count));
    return __res;
}
/* end of additional stuff */

#define __HAVE_ARCH_STRSTR
inline char * strstr(const char * cs,const char * ct)
{
    int d0, d1;
    register char * __res;
    __asm__ __volatile__(
            "movl %6,%%edi\n\t"
            "repne\n\t"
            "scasb\n\t"
            "notl %%ecx\n\t"
            "decl %%ecx\n\t"    /* NOTE! This also sets Z if searchstring='' */
            "movl %%ecx,%%edx\n"
            "1:\tmovl %6,%%edi\n\t"
            "movl %%esi,%%eax\n\t"
            "movl %%edx,%%ecx\n\t"
            "repe\n\t"
            "cmpsb\n\t"
            "je 2f\n\t"         /* also works for empty string, see above */
            "xchgl %%eax,%%esi\n\t"
            "incl %%esi\n\t"
            "cmpb $0,-1(%%eax)\n\t"
            "jne 1b\n\t"
            "xorl %%eax,%%eax\n\t"
            "2:"
            :"=a" (__res), "=&c" (d0), "=&S" (d1)
            :"0" (0), "1" (0xffffffff), "2" (cs), "g" (ct)
                  :"dx", "di");
    return __res;
}

/*
 * This looks horribly ugly, but the compiler can optimize it totally,
 * as we by now know that both pattern and count is constant..
 */
inline void * __constant_c_and_count_memset(void * s, unsigned long pattern, size_t count)
{
    switch (count) {
        case 0:
            return s;
        case 1:
            *(unsigned char *)s = pattern;
            return s;
        case 2:
            *(unsigned short *)s = pattern;
            return s;
        case 3:
            *(unsigned short *)s = pattern;
            *(2+(unsigned char *)s) = pattern;
            return s;
        case 4:
            *(unsigned long *)s = pattern;
            return s;
    }
#define COMMON2(x) \
    __asm__  __volatile__( \
            "rep ; stosl" \
            x \
            : "=&c" (d0), "=&D" (d1) \
            : "a" (pattern),"0" (count/4),"1" ((long) s) \
            : "memory")
    {
        int d0, d1;
        switch (count % 4) {
            case 0: COMMON2(""); return s;
            case 1: COMMON2("\n\tstosb"); return s;
            case 2: COMMON2("\n\tstosw"); return s;
            default: COMMON2("\n\tstosw\n\tstosb"); return s;
        }
    }

#undef COMMON2
}

#define __constant_c_x_memset(s, c, count) \
    (__builtin_constant_p(count) ? \
     __constant_c_and_count_memset((s),(c),(count)) : \
     __constant_c_memset((s),(c),(count)))

#define __memset(s, c, count) \
    (__builtin_constant_p(count) ? \
     __constant_count_memset((s),(c),(count)) : \
     __memset_generic((s),(c),(count)))

#define __HAVE_ARCH_MEMSET
#define memset(s, c, count) \
    (__builtin_constant_p(c) ? \
     __constant_c_x_memset((s),(0x01010101UL*(unsigned char)(c)),(count)) : \
     __memset((s),(c),(count)))

/*
 * find the first occurrence of byte 'c', or 1 past the area if none
 */
#define __HAVE_ARCH_MEMSCAN
inline void * memscan(void * addr, int c, size_t size)
{
    if (!size)
        return addr;
    __asm__("repnz; scasb"
            "jnz 1f"
            "dec %%edi"
            "1:"
            : "=D" (addr), "=c" (size)
            : "0" (addr), "1" (size), "a" (c));
    return addr;
}

#endif
