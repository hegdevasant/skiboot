# -*-Makefile-*-

SUBDIRS += hw
HW_OBJS = fsp.o fsp-console.o
HW=hw/built-in.o

$(HW): $(HW_OBJS:%=hw/%)

