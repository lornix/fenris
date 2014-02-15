/* A quick, dirty, stupid disassembler to test the engine */
/* Compile with  `gcc -I. -O3 -ggdb -L. -ldisasm quikdis.c -o quikdis` */
// tweaked by lcamtuf

#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <elf.h>
#include "libdis.h"

struct changed* CH;

int main( int argc, char* argv[]) {
	int fTarget, entry, x, i=0, n, size;
	unsigned char* buf;
	void * image;
	off_t curr_pos;
	Elf32_Ehdr*  TargetHeader;
	Elf32_Phdr*  ProgramHeader;
	struct stat tmpStat;



   if ( argc < 2) {
		printf("Usage: %s filename\n", argv[0]);
		return 1;
	}

	/* read ELF header */
   fTarget = open( argv[1], O_RDONLY);
	fstat(fTarget, &tmpStat);
	image = mmap(0, tmpStat.st_size, PROT_READ, MAP_SHARED, fTarget, 0);
	if ( (int) image < 1 ) return(-1);
	close( fTarget );
   printf("File name: %s\n", argv[1]);
	TargetHeader = image;

	/* read program header table */
	for ( x = 0; x < TargetHeader->e_phnum; x++){
	ProgramHeader = image + TargetHeader->e_phoff + (x * TargetHeader->e_phentsize);
		/* IF entry point is in this section */
		if ( TargetHeader->e_entry >= ProgramHeader->p_vaddr && 
							 TargetHeader->e_entry <= 
							 ( ProgramHeader->p_vaddr + ProgramHeader->p_filesz) ) 
		{
			/* resolve entry point RVA to a file offset */
			entry = TargetHeader->e_entry - 
					  ( ProgramHeader->p_vaddr - ProgramHeader->p_offset);
			printf("\tDisassembling from entry point at offset %X\n", entry);

			/* read entire program segment into buffer */
			buf = image + entry;
			while (i < (ProgramHeader->p_filesz - entry)){
               CH = disassemble_address(buf + i);
             if (CH->addr || CH->areg[0]) {
               printf("Changed: addr 0x%x: areg %s ireg %s * %d + 0x%x\n",TargetHeader->e_entry + i,CH->areg,CH->ireg,CH->sc,CH->addr);
             }
	     i += CH->size;
			}
		}
	}
	munmap(image, tmpStat.st_size);
	return 0;
}

