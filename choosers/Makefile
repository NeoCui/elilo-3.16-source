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


FILES=

ifeq ($(CONFIG_chooser_simple),y)
FILES +=simple.o
endif

ifeq ($(CONFIG_chooser_textmenu),y)
FILES +=textmenu.o
endif

TARGET=choosers.o

all: $(TARGET)

$(TARGET): $(TOPDIR)/Make.defaults $(FILES)
	@if [ -z "$(FILES)" ]; then \
		echo "You need to define at least one chooser in Make.defaults"; \
		exit 1; \
	fi
	$(LD) $(LD3264) -o $@ -r $(FILES)


clean:
	$(RM) -f $(TARGET) $(FILES)

