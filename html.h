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

*/


#ifndef _HAVE_HTML_H
#define _HAVE_HTML_H

char* header =

       "<body bgcolor=white text=black link=green vlink=magenta alink=red>\n"
       "<font face=\"lucida,courier,monospaced,fixed\" size=-1>\n\n"
       "<table border=0><tr><td>\n<img src=\"http://lcamtuf.coredump.cx/"
       "fenris/fenris-s.jpg\" height=38 width=50 align=left alt=\"\">\n<font "
       "face=\"lucida,courier,monospaced,fixed\" size=-1>\n &nbsp; <b>fenris -"
       " program execution path analysis tool</b> &nbsp; <br> \n<font size=-2>"
       " &nbsp; Developed by Michal Zalewski \n&lt;<a href=\"mailto:lca"
       "mtuf@coredump.cx\">lcamtuf@coredump.cx</a>&gt;\n</td></table>\n"
       "<p>\n\n"
       "<noscript>\n"
       "You are viewing this page with something that is not capable of "
       "executing scripts. If you are using 'lynx', please press Ctrl+V or "
       "run it with '-tagsoup' parameter - default SortaSGML parser will not "
       "render this page 100%% properly (working on that, probably a bug in lynx).\n</noscript>\n\n";


/*
   This is just a script to display href tooltips, where available,
   without destroying lynx layout. It came with the following copyright 
   notice:

   Text Link/Image Map Tooltip Script- 
   (c) Dynamic Drive (www.dynamicdrive.com)
   For full source code, installation instructions,
   100's more DHTML scripts, and Terms Of
   Use, visit dynamicdrive.com
 */

char* ascript =
 
       "\n<script>\n<!--\n"
       "// Your lucky number is 3552664958674928.  Watch for it everywhere.\n"
       "if (!document.layers&&!document.all) event=\"test\"\n"
       "function showtip(current,e,text){\n"
       "  if (document.all){\n"
       "    thetitle=text.split('<br>')\n"
       "    if (thetitle.length>1){\n"
       "      thetitles=''\n"
       "      for (i=0;i<thetitle.length;i++)\n"
       "      thetitles+=thetitle[i]\n"
       "      current.title=thetitles\n"
       "    } else current.title=text\n"
       "  }\n"

       "  else if (document.layers) {\n"
       "    document.tooltip.document.write('<layer bgColor=#00afaf style=\"font-family:lucidatypewriter,fixed;font-size:12px;color:white;\">'+text+'</layer>')\n"
       "    document.tooltip.document.close()\n"
       "    document.tooltip.left=e.pageX+5\n"
       "    document.tooltip.top=e.pageY+5\n"
       "    document.tooltip.visibility=\"show\"\n"
       "  }\n"
       "}\n"

       "function hidetip() {\n"
       "if (document.layers) document.tooltip.visibility=\"hidden\"\n"
       "}\n"
       "// -->\n"
       "</script>\n\n"
       "<div id=\"tooltip\" style=\"position:absolute;visibility:hidden\"></div>\n\n";

char* hinttable = 
       "<table border=1 bgcolor=yellow>"
       "<tr><td><font face=arial,helvetica size=+0><b>symbol</td><td><font face=arial,helvetica size=+0><b>description</td>\n"
       "<td><font face=arial,helvetica size=+0><b>symbol</td><td><font face=arial,helvetica size=+0><b>description</td>\n"
       "<tr><td><font face=arial,helvetica size=-2>.</td><td><font face=arial,helvetica size=-2>buffer / fd</td>\n"
       "<td><font face=arial,helvetica size=-2>:</td><td><font face=arial,helvetica size=-2>used buf / fd</td>\n"
       "<tr><td><font face=arial,helvetica size=-2>r</td><td><font face=arial,helvetica size=-2>read / accessed</td>\n"
       "<td><font face=arial,helvetica size=-2>W</td><td><font face=arial,helvetica size=-2>written</td>\n"
       "<tr><td><font face=arial,helvetica size=-2>X</td><td><font face=arial,helvetica size=-2>read and written</td>\n"
       "<td><font face=arial,helvetica size=-2>*</td><td><font face=arial,helvetica size=-2>discarded</td>\n"
       "<tr><td><font face=arial,helvetica size=-2>S</td><td><font face=arial,helvetica size=-2>source</td>\n"
       "<td><font face=arial,helvetica size=-2>D</td><td><font face=arial,helvetica size=-2>destination</td>\n"
       "<tr><td><font face=arial,helvetica size=-2>+</td><td><font face=arial,helvetica size=-2>fd I/O</td>\n"
       "<td><font face=arial,helvetica size=-2>O</td><td><font face=arial,helvetica size=-2>fd opened</td>\n"
       "<tr><td><font face=arial,helvetica size=-2>#</td><td><font face=arial,helvetica size=-2>fd cloned</td>\n"
       "<td><font face=arial,helvetica size=-2>*</td><td><font face=arial,helvetica size=-2>fd discarded</td>\n"
       "</table><p>\n";

char* finito =
  "<!--- footer.txt --->\n"
  "<br>&nbsp;<p><hr><p><A name=HELP>To get help, please visit "
  "<a href=\"http://lcamtuf.coredump.cx/fenris/\">Fenris project homepage</a> and "
  "read the documentation.<br> <font size=-2 color=#a0a0a0>Developed by "
  "<a href=\"http://lcamtuf.coredump.cx\">Michal Zalewski</a>.\n\n</body>\n</html>";

#define NFI "&nbsp;</td><td><font face=\"courier,fixed\" size=-1>"

#define NAVI "<font size=-2>[ <a href=\"#A1\">flow</a> | " \
              "<a href=\"#A2\">calls</a> | " \
              "<a href=\"#A3\">params</a> | " \
              "<a href=\"#A4\">buffers</a> | " \
              "<a href=\"#A6\">I/O</a> | " \
              "<a href=\"#A5\">raw</a> ]<p>\n"

#define NRO_1 "&nbsp;</td><tr bgcolor=#ffffff><td><font face=\"courier,fixed\" size=-1>"
#define NRO_2 "&nbsp;</td><tr bgcolor=#e0e0e0><td><font face=\"courier,fixed\" size=-1>"

#endif /* ! _HAVE_HTML_H */
