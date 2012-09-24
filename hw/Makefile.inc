# -*-Makefile-*-

SUBDIRS += hw
HW_OBJS = fsp.o fsp-console.o op-panel.o xscom.o
HW=hw/built-in.o

$(HW): $(HW_OBJS:%=hw/%)

