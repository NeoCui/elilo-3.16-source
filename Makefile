#
#  Copyright (C) 2001-2003 Hewlett-Packard Co.
#	Contributed by Stephane Eranian <eranian@hpl.hp.com>
#	Contributed by Fenghua Yu<fenghua.yu@intel.com>
#	Contributed by Chandramouli Narayanan<mouli@linux.intel.com>
#
# This file is part of ELILO, the LINUX EFI boot loader.
#
#  ELILO is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2, or (at your option)
#  any later version.
#
#  ELILO is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with ELILO; see the file COPYING.  If not, write to the Free
#  Software Foundation, 59 Temple Place - Suite 330, Boston, MA
#  02111-1307, USA.
#
# Please check out the elilo.txt for complete documentation on how
# to use this program.
#

SRCDIR = .

VPATH = $(SRCDIR)

include $(SRCDIR)/Make.defaults
TOPDIR = $(SRCDIR)


CRTOBJS       = $(EFICRT0)/crt0-efi-$(ARCH).o
LDSCRIPT      = $(EFICRT0)/elf_$(ARCH)_efi.lds

LDFLAGS	     += -T $(LDSCRIPT) -shared -Bsymbolic -L$(EFILIB) -L$(GNUEFILIB) $(CRTOBJS)
LOADLIBES     = -lefi -lgnuefi $(shell $(CC) $(ARCH3264) -print-libgcc-file-name)
FORMAT        = efi-app-$(ARCH)

FILESYSTEM    =

ifeq ($(CONFIG_localfs),y)
FILESYSTEMS += glue_localfs.o
endif

ifeq ($(CONFIG_ext2fs),y)
FILESYSTEMS += glue_ext2fs.o
endif

ifeq ($(CONFIG_netfs),y)
FILESYSTEMS += glue_netfs.o
endif

SUBDIRS = fs choosers devschemes tools

ifeq ($(ARCH),ia64)
SUBDIRS += ia64
endif

ifeq ($(ARCH),ia32)
SUBDIRS += ia32
endif

ifeq ($(ARCH),x86_64)
SUBDIRS += x86_64
endif

FILES = elilo.o getopt.o strops.o loader.o \
        fileops.o util.o vars.o alloc.o chooser.o  \
	config.o initrd.o alternate.o bootparams.o \
	gunzip.o console.o fs/fs.o \
	choosers/choosers.o \
	devschemes/devschemes.o \
	$(ARCH)/sysdeps.o \
	$(FILESYSTEMS)

TARGETS = elilo.efi

all: check_gcc $(SUBDIRS) $(TARGETS)

elilo.efi: elilo.so

elilo.so: $(FILES)

elilo.o : elilo.c $(ARCH)/sysdeps.h

fileops.o : Make.defaults
chooser.o : Make.defaults

$(SUBDIRS): dummy
	mkdir -p $@
	$(MAKE) -C $@ -f $(SRCDIR)/../$@/Makefile SRCDIR=$(SRCDIR)/../$@ ARCH=$(ARCH)

dummy:

clean:
	@set -e ; for d in $(ALLSUBDIRS) ; do $(MAKE) -C $$d $@ ; done
	rm -f $(TARGETS) *~ *.so $(FILES)

.PRECIOUS: elilo.so

#
# on both platforms you must use gcc 3.0 or higher 
#
check_gcc:
ifeq ($(GCC_VERSION),2)
	@echo "you need to use a version of gcc >= 3.0, you are using `$(CC) --version`"
	@exit 1
endif

include $(SRCDIR)/Make.rules
