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

#ifndef __LOCALFS_H__
#define __LOCALFS_H__

INTERFACE_DECL(_localfs_interface_t);

typedef struct _localfs_interface_t {
	EFI_STATUS (*localfs_name)(struct _localfs_interface_t *this, CHAR16 *name, UINTN maxlen);
	EFI_STATUS (*localfs_open)(struct _localfs_interface_t *this, CHAR16 *name, UINTN *fd);
	EFI_STATUS (*localfs_read)(struct _localfs_interface_t *this, UINTN fd, VOID *buf, UINTN *size);
	EFI_STATUS (*localfs_close)(struct _localfs_interface_t *this, UINTN fd);
	EFI_STATUS (*localfs_infosize)(struct _localfs_interface_t *this, UINTN fd, UINT64 *size);
	EFI_STATUS (*localfs_seek)(struct _localfs_interface_t *this, UINTN fd, UINT64 newpos);
} localfs_interface_t;

#define LOCALFS_PROTOCOL \
    { 0x3a42ff5d, 0x43c9, 0x4db8, {0x82, 0x4e, 0xb8, 0x5b, 0xab, 0x97, 0x63, 0xcc} }

extern EFI_STATUS localfs_install(VOID);
extern EFI_STATUS localfs_uninstall(VOID);

#endif /* __LOCALFS_H__ */
