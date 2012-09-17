# -*-Makefile-*-

SUBDIRS += core
CORE_OBJS = console.o memory.o init.o hdif.o spira.o
CORE=core/built-in.o

$(CORE): $(CORE_OBJS:%=core/%)

