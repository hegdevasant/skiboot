# -*-Makefile-*-

SUBDIRS += core
CORE_OBJS = relocate.o console.o heapstack.o init.o hdif.o spira.o memory.o
CORE_OBJS += lock.o cpu.o utils.o device_tree.o
CORE=core/built-in.o

$(CORE): $(CORE_OBJS:%=core/%)

