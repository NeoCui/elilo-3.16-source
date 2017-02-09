/*
 *  Copyright (C) 2001-2003 Hewlett-Packard Co.
 *	Contributed by Stephane Eranian <eranian@hpl.hp.com>
 *	Contributed by Mike Johnston <johnston@intel.com>
 *	Contributed by Chris Ahna <christopher.j.ahna@intel.com>
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

boot_params_t *param_start = NULL;
UINTN param_size = 0;

UINTN kernel_size = 0x800000;	/* 8M (default x86_64 bzImage size limit) */

static VOID *
bzImage_alloc()
{
	UINTN pages = EFI_SIZE_TO_PAGES(kernel_size);
	int reloc_kernel = 0;
	VOID *kla, *kend = kernel_start + kernel_size;
	UINT32 kalign, kmask;
	boot_params_t *ps = param_start;

	/*
	 * Get address for kernel from header, if applicable & available.
	 */
	if ((ps->s.hdr_major < 2) ||
	    (ps->s.hdr_major == 2 && ps->s.hdr_minor < 5)) {
		reloc_kernel = 0;
	} else {
		if (ps->s.kernel_start >= DEFAULT_KERNEL_START)
			kernel_start = (void *)(UINT64)ps->s.kernel_start;
		reloc_kernel = ps->s.relocatable_kernel;
		kalign = ps->s.kernel_alignment;
		kmask = kalign - 1;
		VERB_PRT(3, Print(L"kernel header (%d.%d) suggests kernel "
			"start at address "PTR_FMT" (%srelocatable!)\n",
			ps->s.hdr_major, ps->s.hdr_minor, ps->s.kernel_start,
			(reloc_kernel ? L"": L"not ")));
	}

	/*
	 * Best effort for old (< 2.6.20) and non-relocatable kernels
	 */
	if (alloc_kmem(kernel_start, pages) == 0) {
		VERB_PRT(3, Print(L"kernel_start: "PTR_FMT" kernel_size: %d\n",
			kernel_start, kernel_size));
		return kernel_start;
	} else if ( ! reloc_kernel ) {
		/*
		 * Couldn't get desired address--just load it anywhere and
		 * (try to) move it later.  It's the only chance for non-
		 * relocatable kernels, but it breaks occassionally...
		 */
		ERR_PRT((L"Kernel header (%d.%d) suggests kernel "
			"start at address "PTR_FMT" (non relocatable!)\n"
			"This address is not available, so an attempt"
			"is made to copy the kernel there later on\n"
			"BEWARE: this is unsupported and may not work.  "
			"Please update your kernel.\n",
			ps->s.hdr_major, ps->s.hdr_minor, ps->s.kernel_start));
		kla = (VOID *)(UINT32_MAX - kernel_size);
		/* NULL would preserve the "anywhere" semantic, */
		/* but it would not prevent allocation above 4GB! */

		if (alloc_kmem_anywhere(&kla, pages) != 0) {
			/* out of luck */
			return NULL;
		}
		VERB_PRT(3, Print(L"kernel_start: "PTR_FMT
			"  kernel_size: %d  loading at: "PTR_FMT"\n",
			kernel_start, kernel_size, kla));
		return kla;
	}


	/* Is 'ps->s.kernel_alignment' guaranteed to be sane? */
	if (kalign < EFI_PAGE_SIZE) {
		kalign = EFI_PAGE_SIZE;
		kmask = EFI_PAGE_MASK;
	}
	DBG_PRT((L"alignment: kernel=0x%x efi_page=0x%x : 0x%x\n",
		ps->s.kernel_alignment, EFI_PAGE_SIZE, kalign));

	/*
	 * Couldn't get the preferred address, but luckily it's
	 * a relocatable kernel, so ...
	 *
	 * 1. use 'find_kernel_memory()' (like Itanium)
	 * 2. try out the 16 lowest possible aligned addresses (> 0)
	 * 3. get enough memory to align "creatively"
	 * 4. forget alignment (and start praying)...
	 */

	/* 1. */
	if ((find_kernel_memory(kernel_start, kend, kalign, &kla) != 0) ||
	    (alloc_kmem(kla, pages) != 0)) {
		kla = NULL;
	}

	/* 2. */
	if ( ! kla && (UINT64)kernel_start < kalign ) {
		int i;
		for ( i = 1; i < 16 && !kla; i++ ) {
			VOID *tmp = (VOID *)((UINT64)kalign * i);
			if (alloc_kmem(tmp, pages) == 0) {
				kla =  tmp;
			}
		}
	}

	/* 3. */
	if ( ! kla ) {
		UINTN apages = EFI_SIZE_TO_PAGES(kernel_size + kmask);
		kla = (VOID *)(UINT32_MAX - kernel_size - kmask);

		if (alloc_kmem_anywhere(&kla, apages) == 0) {
			kla = (VOID *)(((UINT64)kla + kmask) & ~kmask);
		} else {
			kla = NULL;
		}
	}

	/* 4. last resort */
	if ( ! kla ) {
		kla = (VOID *)(UINT32_MAX - kernel_size);
		if (alloc_kmem_anywhere(&kla, pages) != 0) {
			return NULL;
		}
	}

	kernel_start = kla;
	VERB_PRT(1, Print(L"relocating kernel_start: "PTR_FMT
		"  kernel_size: %d\n", kernel_start, kernel_size));
	return kla;
}

static INTN
bzImage_probe(CHAR16 *kname)
{
	EFI_STATUS efi_status;
	UINTN size;
	fops_fd_t fd;
	UINT8 bootsect[512];

	DBG_PRT((L"probe_bzImage_boot()\n"));

	if (!kname) {
		ERR_PRT((L"kname == %xh", kname));
		free_kmem();
		return -1;
	}

	/* 
	 * Open kernel image. 
	 */
	DBG_PRT((L"opening %s...\n", kname));

	efi_status = fops_open(kname, &fd);
	if (EFI_ERROR(efi_status)) {
		ERR_PRT((L"Could not open %s.", kname));
		free_kmem();
		return -1;
	}
	/*
	 * Read boot sector.
	 */

	DBG_PRT((L"\nreading boot sector...\n"));

	size = sizeof bootsect;
	efi_status = fops_read(fd, bootsect, &size);
	if (EFI_ERROR(efi_status) || size != sizeof bootsect) {
		ERR_PRT((L"Could not read boot sector from %s.", kname));
		fops_close(fd);
		free_kmem();
		return -1;
	}
	/*
	 * Verify boot sector signature.
	 */

	if (bootsect[0x1FE] != 0x55 || bootsect[0x1FF] != 0xAA) {
		ERR_PRT((L"%s is not a bzImage kernel image.\n", kname));
		fops_close(fd);
		free_kmem();
		return -1;
	}
	/*
	 * Check for out of range setup data size.
	 * Will almost always be 7, but we will accept 1 to 64.
	 */

	DBG_PRT((L"bootsect[1F1h] == %d setup sectors\n", bootsect[0x1F1]));

	if (bootsect[0x1F1] < 1 || bootsect[0x1F1] > 64) {
		ERR_PRT((L"%s is not a valid bzImage kernel image.",
			kname));
		fops_close(fd);
		free_kmem();
		return -1;
	}
	/*
	 * Allocate and read setup data.
	 */

	DBG_PRT((L"reading setup data...\n"));

	param_size = (bootsect[0x1F1] + 1) * 512;
	param_start = alloc(param_size, EfiLoaderData);

	DBG_PRT((L"param_size=%d param_start=%x", param_size, param_start));

	if (!param_start) {
		ERR_PRT((L"Could not allocate %d bytes of setup data.",
			param_size));
		fops_close(fd);
		free_kmem();
		return -1;
	}

	CopyMem(param_start, bootsect, sizeof bootsect);

	size = param_size - 512;
	efi_status = fops_read(fd, ((UINT8 *)param_start) + 512, &size);

	if (EFI_ERROR(efi_status) || size != param_size - 512) {
		ERR_PRT((L"Could not read %d bytes of setup data.",
			param_size - 512));
		free(param_start);
		param_start = NULL;
		param_size = 0;
		fops_close(fd);
		free_kmem();
		return -1;
	}
	/*
	 * Check for setup data signature.
	 */

	{ 
		UINT8 *c = ((UINT8 *)param_start)+514;
		DBG_PRT((L"param_start(c=%x): %c-%c-%c-%c", 
			c, (CHAR16)c[0],(CHAR16) c[1], (CHAR16)c[2], (CHAR16)c[3]));
	}
	if (CompareMem(((UINT8 *)param_start) + 514, "HdrS", 4)) {
		ERR_PRT((L"%s does not have a setup signature.",
			kname));
		free(param_start);
		param_start = NULL;
		param_size = 0;
		fops_close(fd);
		free_kmem();
		return -1;
	}
	/*
	 * Allocate memory for kernel.
	 */

	kernel_load_address = bzImage_alloc();
	if ( ! kernel_load_address ) {
		ERR_PRT((L"Could not allocate memory for kernel."));
		free(param_start);
		param_start = NULL;
		param_size = 0;
		fops_close(fd);
		return -1;
	}

	/*
	 * Now read the rest of the kernel image into memory.
	 */

	Print(L"Loading kernel %s... ", kname);

	size = kernel_size;
	efi_status = fops_read(fd, kernel_load_address, &size);
	if (EFI_ERROR(efi_status) || size < 0x10000) {
		ERR_PRT((L"Error reading kernel image (0x%x).", efi_status));
		free(param_start);
		param_start = NULL;
		param_size = 0;
		fops_close(fd);
		free_kmem();
		return -1;
	} else {
		Print(L" done\n");
	}

	DBG_PRT((L"kernel image read:  %d bytes, %d Kbytes\n", size, size / 1024));

	/*
	 * Boot sector, setup data and kernel image loaded.
	 */

	fops_close(fd);
	return 0;
}

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */
static INTN
bzImage_load(CHAR16 *kname, kdesc_t *kd)
{
	DBG_PRT((L"load_bzImage_boot()\n"));

	if (!kname || !kd) {
		ERR_PRT((L"kname="PTR_FMT"  kd="PTR_FMT"", kname, kd));
		free(param_start);
		param_start = NULL;
		param_size = 0;
		free_kmem();
		return -1;
	}
	kd->kstart = kd->kentry = kernel_start;
	kd->kend = ((UINT8 *)kd->kstart) + kernel_size;

	DBG_PRT((L"kstart="PTR_FMT"  kentry="PTR_FMT"  kend="PTR_FMT"\n", kd->kstart, kd->kentry, kd->kend));

	return 0;
}

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */
loader_ops_t bzimage_loader = {
	NULL,
	L"bzImage_loader",
	&bzImage_probe,
	&bzImage_load
};
