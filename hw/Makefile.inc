# -*-Makefile-*-

SUBDIRS += hw
HW_OBJS = fsp.o fsp-console.o op-panel.o xscom.o chiptod.o
HW_OBJS += fsp-rtc.o gx.o cec.o
HW=hw/built-in.o

$(HW): $(HW_OBJS:%=hw/%)

