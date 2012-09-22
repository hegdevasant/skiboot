# -*-Makefile-*-

SUBDIRS += asm 
ASM_OBJS = head.o lock.o
ASM=asm/built-in.o

$(ASM): $(ASM_OBJS:%=asm/%)

