# -*-Makefile-*-

SUBDIRS += asm 
ASM_OBJS = head.o
ASM=asm/built-in.o

$(ASM): $(ASM_OBJS:%=asm/%)

