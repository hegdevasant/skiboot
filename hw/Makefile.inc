# -*-Makefile-*-

SUBDIRS += hw
HW_OBJS = fsp.o fsp-console.o fsp-rtc.o fsp-nvram.o op-panel.o
HW_OBJS += xscom.o chiptod.o gx.o cec.o vpd.o
HW_OBJS += p7ioc.o p7ioc-inits.o p7ioc-phb.o
HW_OBJS += p5ioc2.o p5ioc2-phb.o
HW=hw/built-in.o

$(HW): $(HW_OBJS:%=hw/%)

