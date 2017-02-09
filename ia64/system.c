/*
 *  Copyright (C) 2001-2003 Hewlett-Packard Co.
 *	Contributed by Stephane Eranian <eranian@hpl.hp.com>
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

/*
 * this file contains all the IA-64 specific code expected by generic loader
 */
#include <efi.h>
#include <efilib.h>

#include "elilo.h"
#include "loader.h"
#include "private.h"

extern loader_ops_t plain_loader, gzip_loader;

/*
 * IA-64 specific boot paramters initialization routine
 */
INTN
sysdeps_create_boot_params(boot_params_t *bp, CHAR8 *cmdline, memdesc_t *initrd, memdesc_t *vmcode, UINTN *cookie)
{
	UINTN cols, rows;
	SIMPLE_TEXT_OUTPUT_INTERFACE *conout;
	EFI_STATUS status;
	mmap_desc_t mdesc;

	/*
	 * retrieve address of FPSWA interface
	 * if not found, argument is not touched
	 * will be 0 because of Memset()
	 */
	query_fpswa((VOID **)&bp->fpswa);

	if (get_memmap(&mdesc) == -1) return -1;

	DBG_PRT((L"Got memory map @ 0x%lx (%d bytes) with key %d", mdesc.md, mdesc.map_size, mdesc.cookie));

	bp->efi_systab		= (UINTN)systab;
	bp->efi_memmap		= (UINTN)mdesc.md;
	bp->efi_memmap_size	= mdesc.map_size;
	bp->efi_memdesc_size	= mdesc.desc_size;
	bp->efi_memdesc_version = mdesc.desc_version;
	bp->command_line	= (UINTN)cmdline;
	bp->initrd_start	= (UINTN) initrd->start_addr;
	bp->initrd_size		= initrd->size;
	DBG_PRT((L"Got initrd @ 0x%lx (%d bytes)", initrd->start_addr, initrd->size));

	bp->vmcode_start	= (UINTN) vmcode->start_addr;
	bp->vmcode_size		= vmcode->size;
	DBG_PRT((L"Got vmcode @ 0x%lx (%d bytes)", vmcode->start_addr, vmcode->size));

	/* fetch console parameters: */
	conout = systab->ConOut;
	status = conout->QueryMode(conout, conout->Mode->Mode, &cols, &rows);
	if (EFI_ERROR(status)) {
		ERR_PRT((L"boot_params QueryMode failed %r", status));
		goto error;
	}
	DBG_PRT((L"Got console info: cols=%d rows=%d x=%d y=%d",
	      cols, rows, conout->Mode->CursorColumn, conout->Mode->CursorRow));

	bp->console_info.num_cols = cols;
	bp->console_info.num_rows = rows;
	bp->console_info.orig_x = conout->Mode->CursorColumn;
	bp->console_info.orig_y = conout->Mode->CursorRow;

	*cookie = mdesc.cookie;

	return 0;
error:
	/* free descriptors' memory */
	free_memmap(&mdesc);

	return -1;
}

VOID
sysdeps_free_boot_params(boot_params_t *bp)
{
	mmap_desc_t md;

	Memset(&md, 0, sizeof(md));

	md.md = (VOID *)bp->efi_memmap;

	free_memmap(&md);
}

INTN
sysdeps_init(EFI_HANDLE dev)
{
	loader_register(&plain_loader);
	loader_register(&gzip_loader);

	return 0;
}

INTN
sysdeps_initrd_get_addr(kdesc_t *kd, memdesc_t *imem)
{
	/*
	 * We currently place the initrd at the next page aligned boundary
	 * after the kernel. 
	 *
	 * Current kernel implementation requires this (see arch/ia64/kernel/setup.c).
	 *
	 * IMPORTANT: EFI & kernel page sizes may differ. We have no way
	 * of guessing what size the kernel uses. It is the responsibility
	 * of the kernel to adjust.
	 *
	 */
#if 0
	imem->start_addr = (VOID *)ROUNDUP((UINTN)kd->kend, EFI_PAGE_SIZE);
#else
	imem->start_addr = 0; /* let the allocator decide */
#endif

	return 0;
}

VOID *
sysdeps_checkfix_initrd(VOID *start_addr, memdesc_t *imem)
{
	return start_addr;
}

/* Flush data cache [addr; addr + len], and sync with icache.  */
void
flush_dcache (CHAR8 *addr, UINT64 len)
{
  	/* Cache line length is at least 32.  */
	UINT64 a = (UINT64)addr & ~0x1f;

	DBG_PRT((L"Flush 0x%lx-", a));

	/* Flush data.  */
	for (len = (len + 31) & ~0x1f; len > 0; len -= 0x20, a += 0x20)
		asm volatile ("fc %0" : : "r" (a));
	/* Sync and serialize.  Maybe extra.  */
	asm volatile (";; sync.i;; srlz.i;;");

	DBG_PRT((L"0x%lx\n", a));
}
