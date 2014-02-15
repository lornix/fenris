#!/usr/bin/perl

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

# Mom, perl sucks!

if( $#ARGV == 0 && $ARGV[0] eq '-h' ){
print <<_NEG;
	Ragnarok Output Splitter (additional tool)
	Usage:  ragsplit source directory
_NEG
exit;
}

# simple rule
$file = shift; $directory = shift; 
$directory = '.' unless $directory;
$sub_directory = ''; $hasil_opened = 0;
$buffer = ''; $hasil = '';

open(F,$file) or die "Cannot open file $file\n";
while( <F> ){

# track the remarked HTML TAG
#  if( /^\s*%\s*mark\s+(.*?)\s*$/ ){
if( /^\s*<!--\s*-\s+(.*?) --->\s*$/ ){
    my $baru = $1; 
    &save_buffer($hasil);
    $buffer = ''; 
    $hasil = "$directory/$sub_directory/${baru}";
    $hasil =~ s{//}{/};
    next;
    }
# check the directory
  if( /^\s*%\s*dir\s+(.*?)\s*$/ ){
    $sub_directory = $1;
    next;
    }

  $buffer .= $_;
  }
&save_buffer($hasil);
close F;
exit;

sub save_buffer {
  my $file = shift;

  return unless $hasil || $buffer ;
  if( $buffer && !$hasil ){
    die "Cannot find ragnarok tags.";
    }

  if( open(OUT,"<$file") ){
    my $os = $/; undef $/;
    my $sbuffer = <OUT>;
    $/ = $os;
    close OUT;
    return if $buffer eq $sbuffer;
    }
  &make_dir($file);
  open(OUT,">$file") or die "Cannot create output file $file";
  print OUT $buffer;
  close OUT;
  }

sub make_dir {
  my $directory = shift;
  my @dlist = split '/' , $directory;
  pop @dlist; 
  return if $#dlist == -1;

  $root = '';
  for( @dlist ){
    $root .= '/' if $root;
    $root .= $_; 
    mkdir $root, 0777 unless -d $root
    }
  }

