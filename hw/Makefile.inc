# -*-Makefile-*-

SUBDIRS += hw
HW_OBJS = fsp.o fsp-console.o op-panel.o xscom.o chiptod.o
HW_OBJS += fsp-rtc.o gx.o cec.o p7ioc.o p7ioc-inits.o p7ioc-phb.o
HW_OBJS += p5ioc2.o p5ioc2-phb.o
HW=hw/built-in.o

$(HW): $(HW_OBJS:%=hw/%)

