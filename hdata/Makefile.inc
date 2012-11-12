# -*-Makefile-*-

SUBDIRS += hdata
HDATA_OBJS = spira.o cpu.o hdif.o memory.o vpd.o
DEVSRC_OBJ=hdata/built-in.o

$(DEVSRC_OBJ): $(HDATA_OBJS:%=hdata/%)
