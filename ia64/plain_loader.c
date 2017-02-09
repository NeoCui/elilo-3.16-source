/*
 *  Copyright (C) 2001-2003 Hewlett-Packard Co.
 *	Contributed by Stephane Eranian <eranian@hpl.hp.com>
 *
 *  Copyright (C) 2001 Silicon Graphics, Inc.
 *      Contributed by Brent Casavant <bcasavan@sgi.com>
 *
 * This file is part of the ELILO, the EFI Linux boot loader.
 *
 *  ELILO is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 *
 *  ELILO is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with ELILO; see the file COPYING.  If not, write to the Free
 *  Software Foundation, 59 Temple Place - Suite 330, Boston, MA
 *  02111-1307, USA.
 *
 * Please check out the elilo.txt for complete documentation on how
 * to use this program.
 */

#include <efi.h>
#include <efilib.h>

#include "elilo.h"
#include "loader.h"
#include "elf.h"
#include "private.h"

#define LD_NAME L"plain_elf64"

#define PLAIN_MIN_BLOCK_SIZE	sizeof(Elf64_Ehdr) /* see load_elf() for details */

#define SKIPBUFSIZE	2048	/* minimal default size of the skip buffer */
static CHAR8 *skip_buffer;	/* used to skip over unneeded data */
static UINTN skip_bufsize;
static UINTN elf_is_big_endian;	/* true if ELF file is big endian */

static inline UINT64 
bswap64(UINT64 v)
{
        if(elf_is_big_endian) v = __ia64_swab64(v);
        return v;
}

static inline UINT32
bswap32(UINT32 v)
{
        if(elf_is_big_endian) v = __ia64_swab32(v);
        return v;
}

static inline UINT16
bswap16(UINT16 v)
{
        if(elf_is_big_endian) v = __ia64_swab16(v);
        return v;
}

static INTN
is_valid_header(Elf64_Ehdr *ehdr)
{
	UINT16 type, machine;

        if (ehdr->e_ident[EI_DATA] == ELFDATA2MSB) {
		type    = __ia64_swab16(ehdr->e_type);
		machine = __ia64_swab16(ehdr->e_machine);
	} else {
		type    = ehdr->e_type;
		machine = ehdr->e_machine;
	}
	DBG_PRT((L"class=%d type=%d data=%d machine=%d\n", 
		ehdr->e_ident[EI_CLASS],
		type,
		ehdr->e_ident[EI_DATA],
		machine));

	return    ehdr->e_ident[EI_MAG0]  == 0x7f 
	       && ehdr->e_ident[EI_MAG1]  == 'E'
	       && ehdr->e_ident[EI_MAG2]  == 'L'
	       && ehdr->e_ident[EI_MAG3]  == 'F'
	       && ehdr->e_ident[EI_CLASS] == ELFCLASS64 
	       && type                    == ET_EXEC	/* must be executable */
	       && machine                 == EM_IA_64 ? 0 : -1;
}

static INTN
plain_probe(CHAR16 *kname)
{
	Elf64_Ehdr ehdr;
	EFI_STATUS status;
	INTN ret = -1;
	fops_fd_t fd;
	UINTN size = sizeof(ehdr);

	status = fops_open(kname, &fd);
	if (EFI_ERROR(status)) return -1;

	status = fops_read(fd, &ehdr, &size);

	if (EFI_ERROR(status) || size != sizeof(ehdr)) goto error;

	ret = is_valid_header(&ehdr);
error:
	fops_close(fd);
	return ret;
}

/*
 * move skip bytes forward in the file
 * this is required because we cannot assume fileops has
 * seek() capabilities.
 */
static INTN
skip_bytes(fops_fd_t fd, UINTN curpos, UINTN newpos)
{
	EFI_STATUS status;
	UINTN n, skip;

	skip = newpos - curpos;
	/* check if seek capability exists */	

	status = fops_seek(fd, newpos);
	if (status == EFI_SUCCESS) return 0;

	if (status != EFI_UNSUPPORTED) goto error;

	/* unsupported case */

	if (skip_buffer == NULL) {
		skip_bufsize = MAX(skip, SKIPBUFSIZE);
		skip_buffer= (CHAR8 *)alloc(skip_bufsize, EfiLoaderData);
		if (skip_buffer == NULL) return -1;
	}
	while (skip) {
		n = skip > skip_bufsize? skip_bufsize : skip;

		status = fops_read(fd, skip_buffer, &n);
		if (EFI_ERROR(status)) goto error;

		skip -=n;
	}
	return 0;

error:
	ERR_PRT((L"%s : cannot skip %d bytes\n", LD_NAME, n));
	return -1;
}

static INTN
load_elf(fops_fd_t fd, kdesc_t *kd)
{
	Elf64_Ehdr ehdr;
	Elf64_Phdr *phdrs;
	EFI_STATUS status;
	INTN ret = ELILO_LOAD_ERROR;
	UINTN i, total_size = 0;
	UINTN pages, size, bss_sz, osize;
	UINTN offs = 0;
	VOID *low_addr = (VOID *)~0;
	VOID *max_addr = (VOID *)0;
	UINTN load_offset = 0;
	UINTN paddr, memsz, filesz, poffs;
	UINT16 phnum;

	Print(L"Loading Linux... ");

	size = sizeof(ehdr);

	status = fops_read(fd, &ehdr, &size);
	if (EFI_ERROR(status) ||size < sizeof(ehdr)) return ELILO_LOAD_ERROR;

	offs += size;

	/*
	 * do some sanity checking on the file
	 */
	if (is_valid_header(&ehdr) == -1) {
		ERR_PRT((L"%s : not an elf 64-bit file\n", LD_NAME));
		return ELILO_LOAD_ERROR;
	}	 

	/* determine file endianess */
        elf_is_big_endian = ehdr.e_ident[EI_DATA] == ELFDATA2MSB ? 1 : 0;

	VERB_PRT(3, { 
			Print(L"ELF file is %s\n", elf_is_big_endian ? L"big endian" : L"little endian");
			Print(L"Entry point 0x%lx\n", bswap64(ehdr.e_entry));
			Print(L"%d program headers\n", bswap16(ehdr.e_phnum));
			Print(L"%d segment headers\n", bswap16(ehdr.e_shnum));
		   });

	phnum = bswap16(ehdr.e_phnum);

	if (skip_bytes(fd, offs, bswap64(ehdr.e_phoff)) != 0) {
		ERR_PRT((L"%s : skip tp %ld for phdrs failed", LD_NAME, offs));
		return ELILO_LOAD_ERROR;
	}
	offs  = bswap64(ehdr.e_phoff);

	size = osize = phnum*sizeof(Elf64_Phdr);

	DBG_PRT((L"%s : phdrs allocate %d bytes sizeof=%d entsize=%d\n", LD_NAME, size,sizeof(Elf64_Phdr), bswap16(ehdr.e_phentsize)));

	phdrs = (Elf64_Phdr *)alloc(size, 0);
	if (phdrs == NULL) {
		ERR_PRT((L"%s : allocate phdrs failed", LD_NAME));
		return ELILO_LOAD_ERROR;
	}

	status = fops_read(fd, phdrs, &size);
	if (EFI_ERROR(status) || size != osize) {
		ERR_PRT((L"%s : load phdrs failed", LD_NAME, status));
		goto out;
	}
	offs += size;
	/*
	 * First pass to figure out:
	 *	- lowest physical address
	 *	- total memory footprint
	 */
	for (i = 0; i < phnum; i++) {

		paddr = bswap64(phdrs[i].p_paddr);
		memsz = bswap64(phdrs[i].p_memsz);

		DBG_PRT((L"Phdr %d paddr [0x%lx-0x%lx] offset %ld"
			   " filesz %ld memsz=%ld bss_sz=%ld p_type=%d\n",
			   1+i, 
			   paddr, 
			   paddr+bswap64(phdrs[i].p_filesz), 
			   bswap64(phdrs[i].p_offset), 
			   bswap64(phdrs[i].p_filesz), 
			   memsz, 
			   memsz - bswap64(phdrs[i].p_filesz), bswap32(phdrs[i].p_type)));
	
		if (bswap32(phdrs[i].p_type) != PT_LOAD) continue;


		if (paddr < (UINTN)low_addr) low_addr = (VOID *)paddr;

		if (paddr + memsz > (UINTN)max_addr) 
			max_addr = (VOID *)paddr + memsz;
	}

	if ((UINTN)low_addr & (EFI_PAGE_SIZE - 1)) {
		ERR_PRT((L"%s : kernel low address 0x%lx not page aligned\n", LD_NAME, low_addr));
		goto out;
	}

	/* how many bytes are needed to hold the kernel */
	total_size = (UINTN)max_addr - (UINTN)low_addr;

	/* round up to get required number of pages */
	pages = EFI_SIZE_TO_PAGES(total_size);

	/* keep track of location where kernel ends for
	 * the initrd ramdisk (it will be put right after the kernel) 
	 */
	kd->kstart = low_addr;
	kd->kend   = low_addr+ (pages << EFI_PAGE_SHIFT);

	/*
	 * that's the kernel entry point (virtual address)
	 */
	kd->kentry = (VOID *)bswap64(ehdr.e_entry);
	
	if (((UINTN)kd->kentry >> 61) != 0) {
		ERR_PRT((L"%s:  <<ERROR>> entry point is a virtual address 0x%lx : not supported anymore\n", LD_NAME, kd->kentry));
	}

	VERB_PRT(3, {
		Print(L"Lowest PhysAddr: 0x%lx\nTotalMemSize:%d bytes (%d pages)\n",
	      		low_addr, total_size, pages);
		Print(L"Kernel entry @ 0x%lx\n", kd->kentry);
	});

	/*
	 * now allocate memory for the kernel at the exact requested spot
	 */
	if (alloc_kmem(low_addr, pages) == -1) {
		VOID *new_addr;

		VERB_PRT(1, Print(L"%s : AllocatePages(%d, 0x%lx) for kernel failed\n", LD_NAME, pages, low_addr));

		if (ia64_can_relocate() == 0) {
			ERR_PRT((L"relocation is disabled, cannot load kernel"));
			goto out;
		}

		/*
		 * could not allocate at requested spot, try to find a
		 * suitable location to relocate the kernel
		 *
		 * The maximum sized Itanium TLB translation entry is 256 MB.
		 * If we relocate the kernel by this amount we know for sure
		 * that alignment constraints will be satisified, regardless
		 * of the kernel used.
		 */
		Print(L"Attempting to relocate kernel.\n");
		if (find_kernel_memory(low_addr, max_addr, 256*MB, &new_addr) == -1) {
			ERR_PRT((L"%s : find_kernel_memory(0x%lx, 0x%lx, 0x%lx, 0x%lx) failed\n", LD_NAME, low_addr, max_addr, 256*MB, &load_offset));
			goto out;
		}
		/* unsigned arithmetic */
                load_offset = (UINTN) (new_addr - ROUNDDOWN((UINTN) low_addr,256*MB));

		VERB_PRT(3, Print(L"low_addr=0x%lx new_addr=0x%lx offset=0x%lx", low_addr, new_addr, load_offset));

		/*
		 * correct various addesses for non-zero load_offset
		 */
		low_addr = (VOID*) ((UINTN) low_addr + load_offset);
		max_addr = (VOID*) ((UINTN) max_addr + load_offset);
		kd->kstart = (VOID *) ((UINTN) kd->kstart + load_offset);
		kd->kend = (VOID *) ((UINTN) kd->kend + load_offset);
		kd->kentry = (VOID *) ((UINTN) kd->kentry + load_offset);

		/*
		 * try one last time to get memory for the kernel
		 */
		if (alloc_kmem(low_addr, pages) == -1) {
			ERR_PRT((L"%s : AllocatePages(%d, 0x%lx) for kernel failed\n", LD_NAME, pages, low_addr));
			ERR_PRT((L"Relocation by 0x%lx bytes failed.\n", load_offset));
			goto out;
		}
	}

	VERB_PRT(1, Print(L"Press any key to interrupt\n"));

	/* Second pass:
	 * Walk through the program headers
	 * and actually load data into physical memory
	 */
	for (i = 0; i < phnum; i++) {

		/*
		 * Check for pure loadable segment; ignore if not loadable
		 */
		if (bswap32(phdrs[i].p_type) != PT_LOAD) continue;

		poffs = bswap64(phdrs[i].p_offset);

		size = poffs - offs;

		VERB_PRT(3, Print(L"\noff=%ld poffs=%ld size=%ld\n", offs, poffs, size));

		filesz = bswap64(phdrs[i].p_filesz);
                /*
                 * correct p_paddr for non-zero load offset
                 */
		phdrs[i].p_paddr = (Elf64_Addr) ((UINTN) bswap64(phdrs[i].p_paddr) + load_offset);

		/*
		 * Move to the right position
		 */
		if (size && skip_bytes(fd, offs, poffs) != 0) goto out_kernel;

		/*
		 * Keep track of current position in file
		 */
		offs += size;

		/*
		 * How many BSS bytes to clear
		 */
		bss_sz = bswap64(phdrs[i].p_memsz) - filesz;

		VERB_PRT(4, {
			Print(L"\nHeader #%d\n", i);
			Print(L"offset %ld\n", poffs);
			Print(L"Phys addr 0x%lx\n", phdrs[i].p_paddr); /* already endian adjusted */
			Print(L"BSS size %ld bytes\n", bss_sz);
			Print(L"skip=%ld offs=%ld\n", size, offs);
		});

		/*
		 * Read actual segment into memory
		 */
		ret = read_file(fd, filesz, (CHAR8 *)phdrs[i].p_paddr);
		if (ret == ELILO_LOAD_ABORTED) goto load_abort;
		if (ret == ELILO_LOAD_ERROR) goto out;
		if (bswap32(phdrs[i].p_flags) & PF_X)
		  	flush_dcache ((CHAR8 *)phdrs[i].p_paddr, filesz);

		/*
		 * update file position
		 */
		offs += filesz;

		/*
		 * Clear bss section
		 */
		if (bss_sz) Memset((VOID *) phdrs[i].p_paddr+filesz, 0, bss_sz);
	}

	free(phdrs);

	Print(L"..done\n");
	return ELILO_LOAD_SUCCESS;

load_abort:
	Print(L"..Aborted\n");
	ret = ELILO_LOAD_ABORTED;
out_kernel:
	/* free kernel memory */
	free_kmem();
out:
	free(phdrs);
	return ret;
}

static INTN
plain_load_kernel(CHAR16 *kname, kdesc_t *kd)
{	
	INTN ret;
	fops_fd_t fd;
	EFI_STATUS status;

	/*
	 * Moving the open here simplifies the load_elf() error handling
	 */
	status = fops_open(kname, &fd);
	if (EFI_ERROR(status)) return ELILO_LOAD_ERROR;

	Print(L"Loading %s...", kname);

	ret = load_elf(fd, kd);

	fops_close(fd);

	/*
	 * if the skip buffer was ever used, free it
	 */
	if (skip_buffer) {
		free(skip_buffer);
		/* in case we come back */
		skip_buffer = NULL;
	}
	return ret;
}

loader_ops_t plain_loader={
	NULL,
	LD_NAME,
	plain_probe,
	plain_load_kernel
};
