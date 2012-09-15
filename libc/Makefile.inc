LIBCDIR = libc

SUBDIRS += $(LIBCDIR)
LIBC = $(LIBCDIR)/built-in.o

include $(LIBCDIR)/string/Makefile.inc
include $(LIBCDIR)/ctype/Makefile.inc
include $(LIBCDIR)/stdlib/Makefile.inc
include $(LIBCDIR)/stdio/Makefile.inc

$(LIBC): $(STRING) $(CTYPE) $(STDLIB) $(STDIO)

