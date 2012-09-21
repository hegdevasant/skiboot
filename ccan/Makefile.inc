# -*-Makefile-*-

SUBDIRS += ccan ccan/list
CCAN_OBJS = list/list.o
CCAN=ccan/built-in.o

$(CCAN): $(CCAN_OBJS:%=ccan/%)

