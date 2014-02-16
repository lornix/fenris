/*
    fenris - program execution path analysis tool
    ---------------------------------------------

    Copyright (C) 2001, 2002 by Bindview Corporation
    Portions copyright (C) 2001, 2002 by their respective contributors
    Developed and maintained by Michal Zalewski <lcamtuf@coredump.cx>

    Portions of this code are based on libi386 library from 'bastard' project
    developed by mammon and few other guys. Please visit their webpage,
    http://bastard.sourceforge.net to learn more about this very interesting
    project.

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

 */

#ifndef _HAVE_I386_OPCODES_H
#define _HAVE_I386_OPCODES_H

#include "i386.h"

extern instr tbl_Main[];
extern instr tbl_0F[];
extern instr tbl_0F00[];
extern instr tbl_0F01[];
extern instr tbl_0F18[];
extern instr tbl_0F71[];
extern instr tbl_0F72[];
extern instr tbl_0F73[];
extern instr tbl_0FAE[];
extern instr tbl_0FBA[];
extern instr tbl_0FC7[];
extern instr tbl_80[];
extern instr tbl_81[];
extern instr tbl_82[];
extern instr tbl_83[];
extern instr tbl_C0[];
extern instr tbl_C1[];
extern instr tbl_D0[];
extern instr tbl_D1[];
extern instr tbl_D2[];
extern instr tbl_D3[];
extern instr tbl_F6[];
extern instr tbl_F7[];
extern instr tbl_FE[];
extern instr tbl_FF[];

#endif /* _HAVE_I386_OPCODES_H */
