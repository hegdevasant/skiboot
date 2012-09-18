# -*-Makefile-*-

SUBDIRS += ccan
CCAN_OBJS = list/list.o
CCAN=ccan/built-in.o

$(CCAN): $(CCAN_OBJS:%=ccan/%)

