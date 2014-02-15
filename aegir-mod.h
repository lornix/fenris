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

   Here is all you need to write Aegir modules. How to do it?
   Go to doc/debug-api.txt :-)

 */

#ifndef _HAVE_AEGIR_MOD_H
#define _HAVE_AEGIR_MOD_H 1

#include "fdebug.h"

// Send message to Fenris.
extern void* send_message(int mtype,void* data,void* store);

// Destroy async output entity from Fenris.
extern void destroy_async(void);

// Wait for traced process to stop.
extern void wait_for_stopped(void);

// Register new frontend command.
extern void register_command(char* commd,void* handler,char* help);

// Get last async message.
extern char* check_async(void);

#endif /* not _HAVE_AEGIR_MOD_H */

