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

#include <efi.h>
#include <efilib.h>

#include "elilo.h"
#include "fileops.h"

typedef struct {
		UINT32	revision;
		UINT32	reserved;
		VOID	*fpswa;
} fpswa_interface_t;

INTN
query_fpswa(VOID **fpswa)
{
	EFI_HANDLE fpswa_image;
	UINTN size;
	EFI_STATUS status;
	EFI_GUID FpswaProtocol = FPSWA_PROTOCOL;

	DBG_PRT((L"Querying FpswaProtocol"));

	size   = sizeof(EFI_HANDLE);

	status = BS->LocateHandle(ByProtocol, &FpswaProtocol, NULL, &size, &fpswa_image);
	if (EFI_ERROR(status)) {
		ERR_PRT((L"boot_params could not locate FPSWA driver", status));
		return -1;
	 }
	status = BS->HandleProtocol(fpswa_image, &FpswaProtocol, fpswa);
	if (EFI_ERROR(status)) {
		ERR_PRT((L"boot_params FpswaProtocol not able find the interface"));
		return -1;
	} 
	VERB_PRT(3, Print(L"FpswaProtocol = 0x%lx revision=%x\n", *fpswa,
				((fpswa_interface_t *)*fpswa)->revision));
	return 0;
}


static INTN
do_check_fpswa(EFI_HANDLE image, EFI_HANDLE dev, CHAR16 *fpswa_file)
{
	EFI_STATUS status;
	EFI_HANDLE handle;
	EFI_DEVICE_PATH *dp;


	dp = FileDevicePath(dev, fpswa_file);
	if (dp == NULL) {
		ERR_PRT((L"Cannot create FilePath for %s", fpswa_file));
		return -1;
	}
	status = BS->LoadImage(0, image, dp, NULL, 0, &handle);
	if (EFI_ERROR(status)) {
		VERB_PRT(3, Print(L"..not found\n"));
		FreePool(dp);
		return -1;
	}
	VERB_PRT(3, Print(L"..starting.."));

	status = BS->StartImage(handle, 0, 0);
	if (EFI_ERROR(status)) {
		VERB_PRT(3, Print(L"failed (%r)\n", status));
		/* 
		 * StartImage() automatically unloads if error 
		 * FPSWA init code will automatically abort if newer revision
		 * is already installed
		 */	
	} else {
		VERB_PRT(3, Print(L"..ok\n"));
	}
	FreePool(dp);

	return 0;
}

/*
 * If the caller specifies a fpswa filename, then it used instead of the
 * defaults.
 * Return:
 * 	0 : indicates that one fpswa driver was loaded, i.e. an update could be done
 * 	-1: no update was found that would have a more recent version of the driver. This is 
 * 	    not a fatal return value.
 */
INTN
check_fpswa(EFI_HANDLE image, EFI_HANDLE dev, CHAR16 *fpswa_file)
{
	/*
	 * we must use \\ here as this is given to LoadImage() directly
	 *
	 * The FPSWA driver MUST be called fpswa.efi and the FPSWA document
	 * (see developer.intel.com/design/itanium) stipulates that the 
	 * file must be placed in \EFI\Intel Firmware\ (no mention of which
	 * EFI system partition). So elilo will check on all accessible
	 * Fat32+ partition for the existence of this directory and file.
	 */
	static CHAR16 *fpswa_filenames[] ={
		L"\\efi\\intel firmware\\fpswa.efi",
#if 0
		L"\\fpswa.efi",
		L"\\fw\\fpswa.efi",
		L"\\efi\\fpswa.efi",
		L"\\efi\\tools\\fpswa.efi",
		L"\\fpswa.efi",
		L"fpswa.efi",
#endif
	};
	UINTN j, count = sizeof(fpswa_filenames)/sizeof(CHAR16 *);
	UINTN cookie;
	CHAR16 devname[FILENAME_MAXLEN];
	
	if (fpswa_file) {
		INTN r;
		devname[0] = CHAR_NULL;
		r = fops_split_path(fpswa_file, devname);
		if (r == -1) {
			ERR_PRT((L"FPSWA driver filename too long %s", fpswa_file));
			return -1;
		}
		if (devname[0] != CHAR_NULL) {
			if (fops_get_device_handle(devname, &dev) != EFI_SUCCESS) {
				ERR_PRT((L"cannot find device %s for FPSWA driver", devname));
				return -1;
			}
		}
		return do_check_fpswa(image, dev, fpswa_file);
	}

	cookie = 0;
	while (fops_get_next_device(cookie, L"vfat", FILENAME_MAXLEN, &cookie, devname, &dev) == EFI_SUCCESS) {
		for (j = 0; j < count; j++) {
			VERB_PRT(3, Print(L"Trying FPSWA driver %s:%s..", devname, fpswa_filenames[j]));
			/*
			 * we need to do all choices to make sure we pickup
			 * the latest version.
			 */
			do_check_fpswa(image, dev, fpswa_filenames[j]);
		}
	}
	return -1;
}
