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
#include "config.h"
#include "private.h"
#include "sysdeps.h"
#include "getopt.h"

typedef struct {
	CHAR16	fpswa[FILENAME_MAXLEN];
	CHAR16	cmd_fpswa[FILENAME_MAXLEN];
	UINTN allow_relocation;
} ia64_global_config_t;

#define ia64_opt_offsetof(option)	(&((sys_img_options_t *)(0x0))->option)

static ia64_global_config_t ia64_gconf;

/*
 * No IA-64 specific options at this point
 * The last entry in each table MUST be use the OPT_NULL type to terminate
 * the chain.
 */
config_option_t sysdeps_global_options[]={
	{OPT_FILE,	OPT_GLOBAL, L"fpswa",		NULL,	NULL,	ia64_gconf.fpswa},
	{OPT_BOOL,	OPT_GLOBAL, L"relocatable",	NULL,	NULL,	&ia64_gconf.allow_relocation},
};

config_option_t sysdeps_image_options[]={
	{OPT_BOOL,	OPT_IMAGE_SYS,  L"relocatable",	NULL,	NULL,	ia64_opt_offsetof(allow_relocation)},
};


/*
 * IA-64 operations that need to be done only once and just before 
 * entering the main loop of the loader
 * Return:
 * 	 0 if sucessful
 * 	-1 otherwise (will abort execution)
 */
INTN
sysdeps_preloop_actions(EFI_HANDLE dev, CHAR16 **argv, INTN argc, INTN index, EFI_HANDLE image)
{
	/* 
	 * we have separate string to make sure that the command line take precedence over
	 * the config file
	 */
	if (ia64_gconf.cmd_fpswa[0] != CHAR_NULL) {
		check_fpswa(image, dev, ia64_gconf.cmd_fpswa);
	} else if (ia64_gconf.fpswa[0] != CHAR_NULL) 
		check_fpswa(image, dev, ia64_gconf.fpswa);
	else
		check_fpswa(image, dev, NULL);

	return 0;
}

/*
 * Return:
 * 	1: if image or global configuration allows relocation
 * 	0: otherwise
 *
 * It is written has a function rather than a macro to avoid
 * exposing config data structure to the rest of the code in ia64
 */
INTN
ia64_can_relocate(VOID)
{
	return ia64_gconf.allow_relocation == TRUE
	    || (elilo_opt.sys_img_opts && elilo_opt.sys_img_opts->allow_relocation ==TRUE) ? 1 : 0;
}

#define IA64_CMDLINE_OPTIONS	L"rF:"

CHAR16 *
sysdeps_get_cmdline_opts(VOID)
{
	return IA64_CMDLINE_OPTIONS;
}

INTN
sysdeps_getopt(INTN c, INTN optind, CHAR16 *optarg)
{
	INTN ret = 0; /* let's be optimistic ! */

	/*
	 * XXX: for now these command line options have to be global
	 */
	switch(c) {
		case L'r':
			ia64_gconf.allow_relocation = 1;
			break;
		case L'F':
			if (StrLen(Optarg) >= FILENAME_MAXLEN) {
				Print(L"FPSWA filename is limited to %d characters\n", FILENAME_MAXLEN);
				return -1;
			}
			StrCpy(ia64_gconf.cmd_fpswa, Optarg);
			break;
		default:
			ret = -1;
	}
	return ret;
}

VOID
sysdeps_print_cmdline_opts(VOID)
{
	Print(L"-r        kernel image can be relocated if load address inexistent\n");
	Print(L"-F file   name of a specific FPSWA EFI driver to load\n");
}

INTN
sysdeps_register_options(VOID)
{
	INTN ret;

	ret = register_config_options(sysdeps_global_options, 
				      sizeof(sysdeps_global_options)/sizeof(config_option_t),
				      OPTIONS_GROUP_GLOBAL);
	if (ret == -1 ) return ret;

	ret = register_config_options(sysdeps_image_options, 
				      sizeof(sysdeps_image_options)/sizeof(config_option_t),
				      OPTIONS_GROUP_IMAGE);

	return ret;
}
