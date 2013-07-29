# -*-Makefile-*-

SUBDIRS += core
CORE_OBJS = relocate.o console.o heapstack.o init.o chip.o mem_region.o malloc.o
CORE_OBJS += lock.o cpu.o utils.o fdt.o opal.o interrupts.o timebase.o
CORE_OBJS += pci.o pci-opal.o fast-reboot.o device.o exceptions.o trace.o
CORE=core/built-in.o

$(CORE): $(CORE_OBJS:%=core/%)

