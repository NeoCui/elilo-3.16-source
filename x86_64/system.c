/*
 *  Copyright (C) 2001-2003 Hewlett-Packard Co.
 *	Contributed by Stephane Eranian <eranian@hpl.hp.com>
 *	Contributed by Mike Johnston <johnston@intel.com>
 *	Contributed by Chris Ahna <christopher.j.ahna@intel.com>
 *	Contributed by Fenghua Yu <fenghua.yu@intel.com>
 *	Contributed by Bibo Mao <bibo.mao@intel.com>
 *	Contributed by chandramouli narayanan <mouli@linux.intel.com>
 *	Edgar Hucek <hostmaster@ed-soft.at>
 *	
 *  Updated with code to fill bootparam converting EFI memory map to E820 
 *  based on a Linux kernel patch provided by Edgar Hucek
 *  - mouli 06/20/2007
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
 * This file contains all the x86_64 specific code expected by generic loader
 */
#include <efi.h>
#include <efilib.h>
#include <string.h>

#include "elilo.h"
#include "loader.h"
#include "rmswitch.h"

#define DEBUG_CREATE_BOOT_PARAMS 0
#if DEBUG_CREATE_BOOT_PARAMS
#define DPR(a) do { if (elilo_opt.debug) { Print a; } } while ( 0 )
#else
#define DPR(a)
#endif

extern loader_ops_t bzimage_loader, plain_loader, gzip_loader; 

/*
 * Descriptor table base addresses & limits for Linux startup.
 */

dt_addr_t gdt_addr = { 0x800, 0x94000 };
dt_addr_t idt_addr = { 0, 0 }; 

/*
 * Initial GDT layout for Linux startup.
 */

UINT16 init_gdt[] = {
	/* gdt[0]: dummy */
	0, 0, 0, 0, 
	
	/* gdt[1]: unused */
	0, 0, 0, 0,

	/* gdt[2]: code */
	0xFFFF,		/* 4Gb - (0x100000*0x1000 = 4Gb) */
	0x0000,		/* base address=0 */
	0x9A00,		/* code read/exec */
	0x00CF,		/* granularity=4096, 386 (+5th nibble of limit) */

	/* gdt[3]: data */
	0xFFFF,		/* 4Gb - (0x100000*0x1000 = 4Gb) */
	0x0000,		/* base address=0 */
	0x9200,		/* data read/write */
	0x00CF,		/* granularity=4096, 386 (+5th nibble of limit) */
};

UINTN sizeof_init_gdt = sizeof init_gdt;

/*
 * Highest available base memory address.
 *
 * For traditional kernels and loaders this is always at 0x90000.
 * For updated kernels and loaders this is computed by taking the
 * highest available base memory address and rounding down to the
 * nearest 64 kB boundary and then subtracting 64 kB.
 *
 * A non-compressed kernel is automatically assumed to be an updated
 * kernel.  A compressed kernel that has bit 6 (0x40) set in the
 * loader_flags field is also assumed to be an updated kernel.
 */

UINTN high_base_mem = 0x90000;

/*
 * Highest available extended memory address.
 *
 * This is computed by taking the highest available extended memory
 * address and rounding down to the nearest EFI_PAGE_SIZE (usually
 * 4 kB) boundary.  
 * This is only used for backward compatibility.
 */

UINTN high_ext_mem = 32 * 1024 * 1024;

/* This starting address will hold true for all of the loader types for now */
VOID *kernel_start = (VOID *)DEFAULT_KERNEL_START;

/* The kernel may load elsewhere if EFI firmware reserves kernel_start */
VOID *kernel_load_address = (VOID *)DEFAULT_KERNEL_START;

VOID *initrd_start = NULL;
UINTN initrd_size = 0;

INTN e820_map_overflow = 0;

INTN
sysdeps_init(EFI_HANDLE dev)
{
	DBG_PRT((L"sysdeps_init()\n"));

	/*
	 * Register our loader(s)...
	 */

	loader_register(&bzimage_loader);
	loader_register(&plain_loader); 	
	loader_register(&gzip_loader); 
	return 0;
}

/*
 * initrd_get_addr()
 *	Compute a starting address for the initial RAMdisk image.
 *	For now we suggest 'initrd_addr_max' with room for 32MB,
 *	as image->pgcnt is not initialized yet.
 */
INTN
sysdeps_initrd_get_addr(kdesc_t *kd, memdesc_t *imem)
{
	DBG_PRT((L"initrd_get_addr()\n"));

	if (!kd || !imem) {
		ERR_PRT((L"kd="PTR_FMT" imem="PTR_FMT"", kd, imem));
		return -1;
	}

	VERB_PRT(3, Print(L"initrd_addr_max="PTR_FMT" reserve=%d\n",
		param_start->s.initrd_addr_max, 32*MB));

	imem->start_addr = (VOID *)
		(((UINT64)param_start->s.initrd_addr_max - 32*MB + 1)
		& ~EFI_PAGE_MASK);

	VERB_PRT(3, Print(L"initrd start_addr="PTR_FMT" pgcnt=%d\n", 
		imem->start_addr, imem->pgcnt));

	return 0;
}


/*
 * checkfix_initrd()
 *	Check and possibly fix allocation of initrd memory.
 */
VOID *
sysdeps_checkfix_initrd(VOID *start_addr, memdesc_t *imem)
{
	UINTN pgcnt =  EFI_SIZE_TO_PAGES(imem->size);
	UINT64 initrd_addr_max = (UINT64)param_start->s.initrd_addr_max;
	UINT64 ki_max = initrd_addr_max - imem->size + 1;
	VOID *ki_max_addr;

	VERB_PRT( 3, Print(L"loadfile: start_addr="PTR_FMT
		" ki_max_addr="PTR_FMT"\n", start_addr, (VOID *)ki_max));
	if (ki_max > UINT32_MAX) {
		ERR_PRT((L"Force kernel specified initrd_addr_max="PTR_FMT
			" below 4GB\n", (VOID *)initrd_addr_max));
		ki_max = UINT32_MAX - imem->size + 1;
	}
	ki_max_addr = (VOID *)ki_max;

	if ((UINT64)start_addr > ki_max) {
		VERB_PRT(1, Print(L"initrd start_addr="PTR_FMT" above "
			"limit="PTR_FMT"\n", start_addr, ki_max_addr));
		free(start_addr);
		start_addr = NULL;
	}
	/* so either the initial allocation failed or it's been to high! */
	if (start_addr == NULL) {
		start_addr = alloc_pages(pgcnt, EfiLoaderData,
			AllocateMaxAddress, ki_max_addr);
	}
	if ((UINT64)start_addr > ki_max) {
		ERR_PRT((L"Failed to allocate %d pages below %dMB",
			pgcnt, (param_start->s.initrd_addr_max+1)>>20));
		free(start_addr);
		start_addr = NULL;
	}
	return start_addr;
}

VOID
sysdeps_free_boot_params(boot_params_t *bp)
{
	mmap_desc_t md;

	ZeroMem(&md, sizeof md);
	md.md = (VOID *)(UINT64)bp->s.efi_mem_map;
	free_memmap(&md);
}

static VOID find_bits(unsigned long mask, UINT8 *first, UINT8* len) {
	unsigned char bit_pos = 0, bit_len = 0;
	*first =0;
	*len = 0;
	if (mask == 0)
		return;
	while (!(mask & 0x1)) {
		mask = mask >> 1;
		bit_pos++;
	}
	while (mask & 0x1) {
		mask = mask >> 1;
		bit_len++;
	}
	*first = bit_pos;
	*len = bit_len;
}

/*
 * Get video information.
 */
static INTN get_video_info(boot_params_t * bp) {
        EFI_GUID GopProtocol = EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID;
        EFI_GRAPHICS_OUTPUT_PROTOCOL *Gop_interface;
        EFI_GRAPHICS_OUTPUT_MODE_INFORMATION *Gop_info;
        EFI_GRAPHICS_OUTPUT_PROTOCOL_MODE   *Gop_mode = NULL;
        EFI_HANDLE *Gop_handle = NULL;
        EFI_STATUS efi_status;
        UINTN size = 0;
        UINTN size1;
        UINT8 i;

	if (x86_64_text_mode() == 1) {
		Print((L"Skip GOP init, force text-mode.\n"));
		return -1;
	}
	efi_status = uefi_call_wrapper(
			BS->LocateHandle,
			5,
			ByProtocol,
			&GopProtocol,
			NULL,
			&size,
			(VOID **)Gop_handle);
	
	if (EFI_ERROR(efi_status) && efi_status != EFI_BUFFER_TOO_SMALL) {
		Print(L"LocateHandle GopProtocol failed.\n");
		Print(L"--Either no graphics head is installed,\n" \
		       "--efi console is set to serial, or,\n" \
		       "--the EFI firmware version of this machine is\n" \
		       "--older than UEFI 2.0. and does not support GOP");
		Print(L"you can SAFELY IGNORE this error. elilo will\n" \
		       "default to text-mode.\n Alternatively you can " \
		       "now force text mode by setting config variable\n" \
		       "text_mode=1 for x86 in elilo.conf or via cmdline.\n\n");
		Print(L"However if this is the last text output you see\n" \
		       "ensure that your kernel console command line\n " \
		       "variable matches up with the actual efi boot menu\n" \
		       "console output settings.\n\n");
		return -1;
	}
	Gop_handle = alloc(size, 0);
	efi_status = uefi_call_wrapper(
			BS->LocateHandle,
			5,
			ByProtocol,
			&GopProtocol,
			NULL,
			&size,
			(VOID **)Gop_handle);
	if (EFI_ERROR(efi_status)) {
		ERR_PRT((L"LocateHandle GopProtocol failed."));
		free(Gop_handle);
		return -1;
	}

	for (i=0; i < size/sizeof(EFI_HANDLE); i++) {
		Gop_handle += i;
		efi_status = uefi_call_wrapper(
				BS->HandleProtocol,
				3,
				*Gop_handle,
				&GopProtocol,
				&Gop_interface);

		if (EFI_ERROR(efi_status)) {
			continue;
		}
		Gop_mode = Gop_interface->Mode;
		efi_status = uefi_call_wrapper(
				Gop_interface->QueryMode,
				4,
				Gop_interface,
				Gop_mode->Mode,
				&size1,
				&Gop_info);
		if (!EFI_ERROR(efi_status))
			break;
		if (EFI_ERROR(efi_status)) {
			continue;
		}
	}
	if (EFI_ERROR(efi_status) || i > (size/sizeof(EFI_HANDLE))) {
		ERR_PRT((L"HandleProtocol GopProtocol failed."));
		free(Gop_handle);
		return -1;
	}
		
	bp->s.is_vga = 0x70;
	bp->s.orig_cursor_col = 0;
	bp->s.orig_cursor_row = 0;
	bp->s.orig_video_page = 0;
	bp->s.orig_video_mode = 0;
	bp->s.orig_video_cols = 0;
	bp->s.orig_video_rows = 0;
	bp->s.orig_ega_bx = 0;
	bp->s.orig_video_points = 0;

	bp->s.lfb_width = Gop_info->HorizontalResolution;
	bp->s.lfb_height = Gop_info->VerticalResolution;
	bp->s.lfb_base = Gop_mode->FrameBufferBase;
	bp->s.lfb_size = Gop_mode->FrameBufferSize;
	bp->s.lfb_pages = 1;
	bp->s.vesa_seg = 0;
	bp->s.vesa_off = 0;
	if (Gop_info->PixelFormat == PixelRedGreenBlueReserved8BitPerColor) {
		bp->s.lfb_depth = 32;
		bp->s.lfb_red_size = 8;
		bp->s.lfb_red_pos = 0;
		bp->s.lfb_green_size = 8;
		bp->s.lfb_green_pos = 8;
		bp->s.lfb_blue_size = 8;
		bp->s.lfb_blue_pos = 16;
		bp->s.lfb_rsvd_size = 8;
		bp->s.lfb_rsvd_pos = 24;
		bp->s.lfb_line_len = Gop_info->PixelsPerScanLine * 4;

	} else if (Gop_info->PixelFormat == PixelBlueGreenRedReserved8BitPerColor) {
		bp->s.lfb_depth = 32;
		bp->s.lfb_red_size = 8;
		bp->s.lfb_red_pos = 16;
		bp->s.lfb_green_size = 8;
		bp->s.lfb_green_pos = 8;
		bp->s.lfb_blue_size = 8;
		bp->s.lfb_blue_pos = 0;
		bp->s.lfb_rsvd_size = 8;
		bp->s.lfb_rsvd_pos = 24;
		bp->s.lfb_line_len = Gop_info->PixelsPerScanLine * 4;
	} else if (Gop_info->PixelFormat == PixelBitMask) {
		find_bits(Gop_info->PixelInformation.RedMask,
			  &bp->s.lfb_red_pos, &bp->s.lfb_red_size);
		find_bits(Gop_info->PixelInformation.GreenMask,
			  &bp->s.lfb_green_pos, &bp->s.lfb_green_size);
		find_bits(Gop_info->PixelInformation.BlueMask,
			  &bp->s.lfb_blue_pos, &bp->s.lfb_blue_size);
		find_bits(Gop_info->PixelInformation.ReservedMask,
			  &bp->s.lfb_rsvd_pos, &bp->s.lfb_rsvd_size);
		bp->s.lfb_depth = bp->s.lfb_red_size + bp->s.lfb_green_size +
				  bp->s.lfb_blue_size + bp->s.lfb_rsvd_size;
		bp->s.lfb_line_len = (Gop_info->PixelsPerScanLine * bp->s.lfb_depth) / 8;
	} else {
		bp->s.lfb_depth = 4;
		bp->s.lfb_red_size = 0;
		bp->s.lfb_red_pos = 0;
		bp->s.lfb_green_size = 0;
		bp->s.lfb_green_pos = 0;
		bp->s.lfb_blue_size = 0;
		bp->s.lfb_blue_pos = 0;
		bp->s.lfb_rsvd_size = 0;
		bp->s.lfb_rsvd_pos = 0;
		bp->s.lfb_line_len = bp->s.lfb_width / 2;
	}
	return 0;
}

CHAR16 *
StrStr(IN const CHAR16 *h, IN const CHAR16 *n)
{
	const CHAR16 *t = h;
	CHAR16 *res;
	int len = 0, i;

	len = StrLen((CHAR16 *)n);
	while(*t != CHAR_NULL) {
	  res = StrChr( t, n[0]);
	  if (!res) return res;
	  for( i = 1; i < len && res[i] != CHAR_NULL && res[i] == n[i]; i++);
	  if ( i == len ) return res;
	  t = res + 1;
	  if (t > h + CMDLINE_MAXLEN) return (CHAR16 *)0;
	}

	return (CHAR16 *)0;
}

CHAR8 *
StrStr8(IN const CHAR8 *h, IN const CHAR8 *n)
{
	const CHAR8 *t = h;
	CHAR8 *res;
	int len = 0, i;

	len = strlena((CHAR8 *)n);
	while(*t != 0) {
	  res = strchra( t, n[0]);
	  if (!res) return res;
	  for( i = 1; i < len && res[i] != 0 && res[i] == n[i]; i++);
	  if ( i == len ) return res;
	  t = res + 1;
	  if (t > (h + CMDLINE_MAXLEN)) return (CHAR8 *)0;
	}

	return (CHAR8 *)0;
}

/* Convert EFI memory map to E820 map for the operating system 
 * This code is based on a Linux kernel patch submitted by Edgar Hucek
 */

#if DEBUG_CREATE_BOOT_PARAMS
static int e820_max = 6;
#else
static int e820_max = E820_MAX;
#endif

/* Add a memory region to the e820 map */
static void add_memory_region (struct e820entry *e820_map,
			       int *e820_nr_map,
			       unsigned long long start,
			       unsigned long size,
			       unsigned int type)
{
	int x = *e820_nr_map;
	static unsigned long long estart = 0ULL;
	static unsigned long esize = 0L;
	static unsigned int etype = -1;
	static int merge = 0;

	if (x == 0)
		DPR((L"AMR: %3s %4s %16s/%12s/%s\n",
			L"idx", L" ", L"start", L"size", L"type"));

	/* merge adjacent regions of same type */
	if ((x > 0) && e820_map[x-1].addr + e820_map[x-1].size == start
	    && e820_map[x-1].type == type) {
		e820_map[x-1].size += size;
		estart = e820_map[x-1].addr;
		esize  = e820_map[x-1].size;
		etype  = e820_map[x-1].type;
		merge++;
		return;
	}
	/* fill up to E820_MAX */
	if ( x < e820_max ) {
		e820_map[x].addr = start;
		e820_map[x].size = size;
		e820_map[x].type = type;
		(*e820_nr_map)++;
		if (merge) DPR((L"AMR: %3d ==>  %016llx/%012lx/%d (%d)\n",
				x-1, estart, esize, etype, merge));
		merge=0;
		DPR((L"AMR: %3d add  %016llx/%012lx/%d\n",
			x, start, size, type));
		return;
	}
	/* different type means another region didn't fit */
	/* or same type, but there's a hole */
	if (etype != type || (estart + esize) != start) {
		if (merge) DPR((L"AMR: %3d ===> %016llx/%012lx/%d (%d)\n",
			e820_map_overflow, estart, esize, etype, merge));
		merge = 0;
		estart = start;
		esize = size;
		etype = type;
		e820_map_overflow++;
		DPR((L"AMR: %3d OVER %016llx/%012lx/%d\n",
			 e820_map_overflow, start, size, type));
		return;
	}
	/* same type and no hole, merge it */
	estart += esize;
	esize += size;
	merge++;
}

void fill_e820map(boot_params_t *bp, mmap_desc_t *mdesc)
{
	int nr_map, e820_nr_map = 0, i;
	UINT64 start, end, size;
	EFI_MEMORY_DESCRIPTOR	*md, *p;
	struct e820entry *e820_map;

	nr_map = mdesc->map_size/mdesc->desc_size;
	e820_map = (struct e820entry *)bp->s.e820_map;
			
	for (i = 0, p = mdesc->md; i < nr_map; i++)
	{
		md = p;
		switch (md->Type) {
		case EfiACPIReclaimMemory:
			add_memory_region(e820_map, &e820_nr_map,
					  md->PhysicalStart,
					  md->NumberOfPages << EFI_PAGE_SHIFT,
					  E820_ACPI);
			break;
		case EfiRuntimeServicesCode:
			add_memory_region(e820_map, &e820_nr_map,
					  md->PhysicalStart,
					  md->NumberOfPages << EFI_PAGE_SHIFT,
					  E820_EXEC_CODE);
			break;
		case EfiRuntimeServicesData:
		case EfiReservedMemoryType:
		case EfiMemoryMappedIO:
		case EfiMemoryMappedIOPortSpace:
		case EfiUnusableMemory:
		case EfiPalCode:
			add_memory_region(e820_map, &e820_nr_map,
					  md->PhysicalStart,
					  md->NumberOfPages << EFI_PAGE_SHIFT,
					  E820_RESERVED);
			break;
		case EfiLoaderCode:
		case EfiLoaderData:
		case EfiBootServicesCode:
		case EfiBootServicesData:
		case EfiConventionalMemory:
			start = md->PhysicalStart;
			size = md->NumberOfPages << EFI_PAGE_SHIFT;
			end = start + size;
			/* Fix up for BIOS that claims RAM in 640K-1MB region */
			if (start < 0x100000ULL && end > 0xA0000ULL) {
				if (start < 0xA0000ULL) {
					/* start < 640K
					 * set memory map from start to 640K
					 */
					add_memory_region(e820_map,
							  &e820_nr_map,
							  start,
							  0xA0000ULL-start,
							  E820_RAM);
				}
				if (end <= 0x100000ULL)
					continue;
				/* end > 1MB
				 * set memory map avoiding 640K to 1MB hole
				 */
				start = 0x100000ULL;
				size = end - start;
			}
			add_memory_region(e820_map, &e820_nr_map,
					  start, size, E820_RAM);
			break;
		case EfiACPIMemoryNVS:
			add_memory_region(e820_map, &e820_nr_map,
					  md->PhysicalStart,
					  md->NumberOfPages << EFI_PAGE_SHIFT,
					  E820_NVS);
			break;
		default:
			/* We should not hit this case */
			DBG_PRT((L"hit default!?"));
			add_memory_region(e820_map, &e820_nr_map,
					  md->PhysicalStart,
					  md->NumberOfPages << EFI_PAGE_SHIFT,
					  E820_RESERVED);
			break;
		}
		p = NextMemoryDescriptor(p, mdesc->desc_size); 
	}
	bp->s.e820_nrmap = e820_nr_map;
}

/*
 * x86_64 specific boot parameters initialization routine
 *
 * Note: debug and verbose messages have already been turned off!
 */
INTN
sysdeps_create_boot_params(
	boot_params_t *bp,
	CHAR8 *cmdline,
	memdesc_t *initrd,
	memdesc_t *vmcode,
	UINTN *cookie)
{
	mmap_desc_t mdesc;
	EFI_STATUS efi_status;
	UINTN rows, cols;
	UINT8 row, col;
	UINT8 mode;
	UINT16 hdr_version;
	UINT8 e820_map_overflow_warned = 0;

#if DEBUG_CREATE_BOOT_PARAMS
	elilo_opt.debug=1;
	elilo_opt.verbose=5;
#endif

	DBG_PRT((L"fill_boot_params()\n"));

	if (!bp || !cmdline || !initrd || !cookie) {
		ERR_PRT((L"bp="PTR_FMT"  cmdline="PTR_FMT"  initrd="PTR_FMT" cookie="PTR_FMT"",
			bp, cmdline, initrd, cookie));

		if (param_start != NULL) {
			free(param_start);
			param_start = NULL;
			param_size = 0;
		}
		free_kmem();
		return -1;
	}

	/*
	 * Copy temporary boot sector and setup data storage to
	 * elilo allocated boot parameter storage.  We only need
	 * the first two sectors (1K).  The rest of the storage
	 * can be used by the command line.
	 */
	if (param_start != NULL) {
		CopyMem(bp, param_start, 0x2000);
	}

	/*
	 * Save off our header revision information.
	 */
	hdr_version = (bp->s.hdr_major << 8) | bp->s.hdr_minor;

	/*
	 * Do NOT clear out unknown memory in boot sector image.
	 * This breaks boot protocol >= 2.10 (2.6.31).
	 */

	/*
	 * Tell kernel this was loaded by an advanced loader type.
	 * If this field is zero, the initrd_start and initrd_size
	 * fields are ignored by the kernel.
	 */

	bp->s.loader_type = LDRTYPE_ELILO;

	/*
	 * Setup command line information.
	 */

	bp->s.cmdline_magik = CMDLINE_MAGIK;
	bp->s.cmdline_offset = (UINT8 *)cmdline - (UINT8 *)bp;

	/* 
	 * Clear out the cmdline_addr field so the kernel can find 
	 * the cmdline.
	 */
	bp->s.cmdline_addr = 0x0;

	/*
	 * Setup hard drive parameters.
	 * %%TBD - It should be okay to zero fill the hard drive
	 * info buffers.  The kernel should do its own detection.
	 */

	ZeroMem(bp->s.hd0_info, sizeof bp->s.hd0_info);
	ZeroMem(bp->s.hd1_info, sizeof bp->s.hd1_info);

	/*
	 * Memory info.
	 */

	bp->s.alt_mem_k = high_ext_mem / 1024;

	if (bp->s.alt_mem_k <= 65535) 
		bp->s.ext_mem_k = (UINT16)bp->s.alt_mem_k;
	else 
		bp->s.ext_mem_k = 65535;

	/*
	 * Initial RAMdisk and root device stuff.
	 */

	DBG_PRT((L"initrd->start_addr="PTR_FMT"  initrd->pgcnt=%d\n",
		initrd->start_addr, initrd->pgcnt));

	/* 'ramdisk_flags' (@0x1F8) is called 'ram_size' in the meantime, */
	/* see Documentation/x86/boot.txt. */
	if (initrd->start_addr && initrd->pgcnt) {
		if ( (UINT64)initrd->start_addr > UINT32_MAX ) {
			ERR_PRT((L"Start of initrd out of reach (>4GB)."));
			free_kmem();
			return -1;
		}
		/* %%TBD - This will probably have to be changed. */
		bp->s.initrd_start = (UINT32)(UINT64)initrd->start_addr;
		bp->s.initrd_size = (UINT32)(initrd->size);
	} else {
		bp->s.initrd_start = 0;
		bp->s.initrd_size = 0;
	}

	/*
	 * APM BIOS info.
	 */
	bp->s.apm_bios_ver = NO_APM_BIOS;
	bp->s.bios_code_seg = 0;
	bp->s.bios_entry_point = 0;
	bp->s.bios_code_seg16 = 0;
	bp->s.bios_data_seg = 0;
	bp->s.apm_bios_flags = 0;
	bp->s.bios_code_len = 0;
	bp->s.bios_data_len = 0;

	/*
	 * MCA BIOS info (misnomer).
	 */
	bp->s.mca_info_len = 0;
	ZeroMem(bp->s.mca_info_buf, sizeof bp->s.mca_info_buf);

	/*
	 * EFI loader signature 
	 */
	CopyMem(bp->s.efi_loader_sig, EFI_LOADER_SIG_X64, 4);

	/*
	 * Kernel entry point.
	 */
	if ( (UINT64)kernel_start != (UINT32)(UINT64)kernel_start ) {
		ERR_PRT((L"Start of kernel (will be) out of reach (>4GB)."));
		free_kmem();
		return -1;
	}
	bp->s.kernel_start = (UINT32)(UINT64)kernel_start;

	/*
	 * When changing stuff in the parameter structure compare
	 * the offsets of the fields with the offsets used in the
	 * boot sector and setup source files.
	 *   arch/x86_64/boot/bootsect.S
	 *   arch/x86_64/boot/setup.S
	 *   arch/x86_64/kernel/setup.c
	 *   include/asm-x86_64/setup.h (2.5/2.6)
	 */

#define CHECK_OFFSET(n, o, f) \
{ \
	UINTN p = (UINT8 *)&bp->s.n - (UINT8 *)bp; \
	UINTN q = (UINTN)(o); \
	if (p != q) { \
		test |= 1; \
		Print(L"%20a:  %3xh  %3xh  ", #n, p, q); \
		if (*f) { \
			Print(f, bp->s.n); \
		} \
		Print(L"\n"); \
	} \
}

#define WAIT_FOR_KEY() \
{ \
	EFI_INPUT_KEY key; \
	while (uefi_call_wrapper(ST->ConIn->ReadKeyStroke, 2, ST->ConIn, &key) != EFI_SUCCESS) { \
		; \
	} \
}
	{
		UINTN test = 0;

		CHECK_OFFSET(orig_cursor_col, 0x00, L"%xh");
		CHECK_OFFSET(orig_cursor_row, 0x01, L"%xh");
		CHECK_OFFSET(ext_mem_k, 0x02, L"%xh");
		CHECK_OFFSET(orig_video_page, 0x04, L"%xh");
		CHECK_OFFSET(orig_video_mode, 0x06, L"%xh");
		CHECK_OFFSET(orig_video_cols, 0x07, L"%xh");
		CHECK_OFFSET(orig_ega_bx, 0x0A, L"%xh");
		CHECK_OFFSET(orig_video_rows, 0x0E, L"%xh");
		CHECK_OFFSET(is_vga, 0x0F, L"%xh");
		CHECK_OFFSET(orig_video_points, 0x10, L"%xh");
		CHECK_OFFSET(lfb_width, 0x12, L"%xh");
		CHECK_OFFSET(lfb_height, 0x14, L"%xh");
		CHECK_OFFSET(lfb_depth, 0x16, L"%xh");
		CHECK_OFFSET(lfb_base, 0x18, L"%xh");
		CHECK_OFFSET(lfb_size, 0x1C, L"%xh");
		CHECK_OFFSET(cmdline_magik, 0x20, L"%xh");
		CHECK_OFFSET(cmdline_offset, 0x22, L"%xh");
		CHECK_OFFSET(lfb_line_len, 0x24, L"%xh");
		CHECK_OFFSET(lfb_red_size, 0x26, L"%xh");
		CHECK_OFFSET(lfb_red_pos, 0x27, L"%xh");
		CHECK_OFFSET(lfb_green_size, 0x28, L"%xh");
		CHECK_OFFSET(lfb_green_pos, 0x29, L"%xh");
		CHECK_OFFSET(lfb_blue_size, 0x2A, L"%xh");
		CHECK_OFFSET(lfb_blue_pos, 0x2B, L"%xh");
		CHECK_OFFSET(lfb_rsvd_size, 0x2C, L"%xh");
		CHECK_OFFSET(lfb_rsvd_pos, 0x2D, L"%xh");
		CHECK_OFFSET(vesa_seg, 0x2E, L"%xh");
		CHECK_OFFSET(vesa_off, 0x30, L"%xh");
		CHECK_OFFSET(lfb_pages, 0x32, L"%xh");
		CHECK_OFFSET(lfb_reserved, 0x34, L"");
		CHECK_OFFSET(apm_bios_ver, 0x40, L"%xh");
		CHECK_OFFSET(bios_code_seg, 0x42, L"%xh");
		CHECK_OFFSET(bios_entry_point, 0x44, L"%xh");
		CHECK_OFFSET(bios_code_seg16, 0x48, L"%xh");
		CHECK_OFFSET(bios_data_seg, 0x4A, L"%xh");
		CHECK_OFFSET(apm_bios_flags, 0x4C, L"%xh");
		CHECK_OFFSET(bios_code_len, 0x4E, L"%xh");
		CHECK_OFFSET(bios_data_len, 0x52, L"%xh");
		CHECK_OFFSET(hd0_info, 0x80, L"");
		CHECK_OFFSET(hd1_info, 0x90, L"");
		CHECK_OFFSET(mca_info_len, 0xA0, L"%xh");
		CHECK_OFFSET(mca_info_buf, 0xA2, L"");
		CHECK_OFFSET(efi_loader_sig, 0x1C0, L"'%-4.4a'");
		CHECK_OFFSET(efi_sys_tbl, 0x1C4, L"%xh");
		CHECK_OFFSET(efi_mem_desc_size, 0x1C8, L"%xh");
		CHECK_OFFSET(efi_mem_desc_ver, 0x1CC, L"%xh");
		CHECK_OFFSET(efi_mem_map, 0x1D0, L"%xh");
		CHECK_OFFSET(efi_mem_map_size, 0x1D4, L"%xh");
		CHECK_OFFSET(efi_sys_tbl_hi, 0x1D8, L"%xh");
		CHECK_OFFSET(efi_mem_map_hi, 0x1DC, L"%xh");
		CHECK_OFFSET(alt_mem_k, 0x1E0, L"%xh");
		CHECK_OFFSET(setup_sectors, 0x1F1, L"%xh");
		CHECK_OFFSET(mount_root_rdonly, 0x1F2, L"%xh");
		CHECK_OFFSET(sys_size, 0x1F4, L"%xh");
		CHECK_OFFSET(video_mode_flag, 0x1FA, L"%xh");
		CHECK_OFFSET(orig_root_dev, 0x1FC, L"%xh");
		CHECK_OFFSET(boot_flag, 0x1FE, L"%xh");
		CHECK_OFFSET(jump, 0x200, L"%xh");
		CHECK_OFFSET(setup_sig, 0x202, L"'%-4.4a'");
		CHECK_OFFSET(hdr_minor, 0x206, L"%xh");
		CHECK_OFFSET(hdr_major, 0x207, L"%xh");
		CHECK_OFFSET(rm_switch, 0x208, L"%xh");
		CHECK_OFFSET(start_sys_seg, 0x20C, L"%xh");
		CHECK_OFFSET(kernel_verstr_offset, 0x20E, L"%xh");
		CHECK_OFFSET(loader_type, 0x210, L"%xh");
		CHECK_OFFSET(loader_flags, 0x211, L"%xh");
		CHECK_OFFSET(setup_move_size, 0x212, L"%xh");
		CHECK_OFFSET(kernel_start, 0x214, L"%xh");
		CHECK_OFFSET(initrd_start, 0x218, L"%xh");
		CHECK_OFFSET(initrd_size, 0x21C, L"%xh");
		CHECK_OFFSET(heap_end_ptr, 0x224, L"%xh");
		CHECK_OFFSET(cmdline_addr, 0x228, L"%xh");
		CHECK_OFFSET(e820_map, 0x2D0, L"%xh");

		if (test) {
			ERR_PRT((L"Boot sector and/or setup parameter alignment error."));
			free_kmem();
			return -1;
		}
	}

	/*
	 * Get video information.
	 * Do this last so that any other cursor positioning done
	 * in the fill routine gets accounted for.
	 */

	if (!get_video_info(bp)) goto do_memmap;
		
	/* Do the old text mode */
	efi_status = uefi_call_wrapper(
		ST->ConOut->QueryMode,
		4,
		ST->ConOut,
		ST->ConOut->Mode->Mode,
		&cols,
		&rows);

	if (EFI_ERROR(efi_status)) {
		ERR_PRT((L"QueryMode failed.  Fake it."));
		mode = 3;
		rows = 25;
		cols = 80;
		row = 24;
		col = 0;
	} else {
		mode = (UINT8)ST->ConOut->Mode->Mode;
		col = (UINT8)ST->ConOut->Mode->CursorColumn;
		row = (UINT8)ST->ConOut->Mode->CursorRow;
	}

	bp->s.orig_cursor_col = col;
	bp->s.orig_cursor_row = row;
	bp->s.orig_video_page = 0;
	bp->s.orig_video_mode = mode;
	bp->s.orig_video_cols = (UINT8)cols;
	bp->s.orig_video_rows = (UINT8)rows;

	bp->s.orig_ega_bx = 0;
	bp->s.is_vga = 0;
	bp->s.orig_video_points = 16; 

	bp->s.lfb_width = 0;
	bp->s.lfb_height = 0;
	bp->s.lfb_depth = 0;
	bp->s.lfb_base = 0;
	bp->s.lfb_size = 0;
	bp->s.lfb_line_len = 0;
	bp->s.lfb_red_size = 0;
	bp->s.lfb_red_pos = 0;
	bp->s.lfb_green_size = 0;
	bp->s.lfb_green_pos = 0;
	bp->s.lfb_blue_size = 0;
	bp->s.lfb_blue_pos = 0;
	bp->s.lfb_rsvd_size = 0;
	bp->s.lfb_rsvd_pos = 0;
	bp->s.lfb_pages = 0;
	bp->s.vesa_seg = 0;
	bp->s.vesa_off = 0;

do_memmap:
	/*
	 * Get memory map description and cookie for ExitBootServices()
	 */

	if (get_memmap(&mdesc)) {
		ERR_PRT((L"Could not get memory map."));
		free_kmem();
		return -1;
	}
	*cookie = mdesc.cookie;
	bp->s.efi_mem_map = (UINT32)(unsigned long)mdesc.md;
	bp->s.efi_mem_map_size = mdesc.map_size;
	bp->s.efi_mem_desc_size = mdesc.desc_size;
	bp->s.efi_mem_desc_ver = mdesc.desc_version;
	bp->s.efi_sys_tbl = (UINT32)(unsigned long)systab;
	bp->s.efi_mem_map_hi = (unsigned long)mdesc.md >> 32;
	bp->s.efi_sys_tbl_hi = (unsigned long)systab >> 32;
	/* Now that we have EFI memory map, convert it to E820 map 
	 * and update the bootparam accordingly
	 */
	fill_e820map(bp, &mdesc);

#if DEBUG_CREATE_BOOT_PARAMS
	if ( e820_map_overflow == 0 )
		e820_map_overflow = -1; /* force second get_memmap()! */
#endif
	if (e820_map_overflow && !e820_map_overflow_warned) {
		CHAR8 *aem = (CHAR8 *)"add_efi_memmap";
		e820_map_overflow_warned++;

#if DEBUG_CREATE_BOOT_PARAMS
		elilo_opt.debug=0;
		elilo_opt.verbose=0;
#endif
		if (e820_map_overflow == -1 || StrStr8(cmdline, aem)) {
			/* Print(L"...mapping again, silently!\n"); */
			goto do_memmap;
		}

		Print(L"\nCAUTION: EFI memory map has %d more entr%a"
			" than E820 map supports.\n"
			"To access all memory, '%a' may be necessary.\n\n",
			e820_map_overflow, (e820_map_overflow==1)?"y":"ies",
			aem);
		goto do_memmap;
	}
	
	return 0;
}
