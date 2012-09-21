# -*-Makefile-*-

SUBDIRS += core
CORE_OBJS = console.o heapstack.o init.o hdif.o spira.o
CORE=core/built-in.o

$(CORE): $(CORE_OBJS:%=core/%)

