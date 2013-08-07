# -*-Makefile-*-

SUBDIRS += hw
HW_OBJS = fsp.o fsp-console.o fsp-rtc.o fsp-nvram.o op-panel.o
HW_OBJS += fsp-sysparam.o
HW_OBJS += xscom.o chiptod.o gx.o cec.o vpd.o lpc.o lpc-uart.o
HW_OBJS += slw.o
HW_OBJS += p7ioc.o p7ioc-inits.o p7ioc-phb.o
HW_OBJS += p5ioc2.o p5ioc2-phb.o
HW_OBJS += phb3.o
HW=hw/built-in.o

$(HW): $(HW_OBJS:%=hw/%)

