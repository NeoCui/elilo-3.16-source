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
 * This file is used to define all the IA64-specific data structures, functions, 
 * and constants used by the generic ELILO. 
 *
 * For things specific to this platform use private.h instead
 */
#ifndef __ELILO_SYSDEPS_IA64_H__
#define __ELILO_SYSDEPS_IA64_H__

#define ELILO_ARCH	"IA-64" /* ASCII string ! */

/* in respective assembly files */
extern VOID Memset(VOID *, INTN, UINTN);
extern VOID Memcpy(VOID *, VOID *, UINTN);

extern VOID sysdep_register_options(VOID);

/*
 * This version must match the one in the kernel
 */
typedef struct ia64_boot_params {
	/*
	 * The following three pointers MUST point to memory that is marked
	 * as EfiRuntimeServicesData so that the kernel doesn't think the
	 * underlying memory is free.
	 */
	UINTN command_line;		/* physical address of command line arguments */
	UINTN efi_systab;		/* physical address of EFI system table */
	UINTN efi_memmap;		/* physical address of EFI memory map */
	UINTN efi_memmap_size;		/* size of EFI memory map */
	UINTN efi_memdesc_size;	/* size of an EFI memory map descriptor */
	UINT32 efi_memdesc_version;	/* descriptor version */
	struct {
		UINT16 num_cols;	/* number of columns on console output device */
		UINT16 num_rows;	/* number of rows on console output device */
		UINT16 orig_x;		/* cursor's x position */
		UINT16 orig_y;		/* cursor's y position */
	} console_info;
	UINTN fpswa;			/* physical address of fpswa interface */
	UINTN initrd_start;		/* virtual address where the initial ramdisk begins */
	UINTN initrd_size;		/* how big is the initial ramdisk */

	UINTN vmcode_start;		/* virtual address where the boot time vmcode begins */
	UINTN vmcode_size;		/* how big is the boot module */
	UINTN loader_addr;		/* start address of boot loader */
	UINTN loader_size;		/* size of loader code & data */

} boot_params_t;

typedef struct sys_img_options {
	UINT8 dummy; 			/* forces non-zero offset for first field */
	UINT8 allow_relocation;		/* allow kernel relocation on allocation error */
} sys_img_options_t;

/*
 * How to jump to kernel code
 */
static inline void
start_kernel(VOID *kentry, VOID *bp)
{
        asm volatile ("mov r28=%1; br.sptk.few %0" :: "b"(kentry),"r"(bp));
}

static inline UINT64
__ia64_swab64 (UINT64 x)
{
	UINT64 result;

	asm volatile ("mux1 %0=%1,@rev" : "=r" (result) : "r" (x));
	return result;
}

static inline UINT32
__ia64_swab32 (UINT32 x)
{
	return __ia64_swab64(x) >> 32;
}

static inline UINT16
__ia64_swab16(UINT16 x)
{
	return __ia64_swab64(x) >> 48;
}

#endif /* __ELILO_SYSDEPS_IA64_H__ */
