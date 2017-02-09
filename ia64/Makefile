#
#  Copyright (C) 2001-2003 Hewlett-Packard Co.
#	Contributed by Stephane Eranian <eranian@hpl.hp.com>
#
# This file is part of the ELILO, the EFI Linux boot loader.
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

include $(SRCDIR)/../Make.defaults
include $(SRCDIR)/../Make.rules

TOPDIR=$(SRCDIR)/..


FILES=system.o config.o fpswa.o plain_loader.o gzip_loader.o \
      gzip.o memset.o memcpy.o setjmp.o longjmp.o

TARGET=sysdeps.o

all: $(TARGET)

$(TARGET): $(FILES)
	$(LD) -o $@ -r $(FILES)

clean:
	$(RM) -f $(TARGET) $(FILES)
