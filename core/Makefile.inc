# -*-Makefile-*-

SUBDIRS += core
CORE_OBJS = console.o memory.o init.o spira.o
CORE=core/built-in.o

$(CORE): $(CORE_OBJS:%=core/%)

