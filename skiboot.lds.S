/* (C) Copyright IBM Corp., 2013 and provided pursuant to the Technology
 * Licensing Agreement between Google Inc. and International Business
 * Machines Corporation, IBM License Reference Number AA130103030256 and
 * confidentiality governed by the Parties’ Mutual Nondisclosure Agreement
 * number V032404DR, executed by the parties on November 6, 2007, and
 * Supplement V032404DR-3 dated August 16, 2012 (the “NDA”). */
#include <config.h>

ENTRY(boot_entry);
SECTIONS
{
	. = 0;

	.head : {
		*(.head)
	}

	. = SPIRA_OFF;
	.spira : {
		*(.spira.data)
	}

	. = PROCIN_OFF;
	.procin.data : {
		*(.procin.data)
	}

 	.text : {
		*(.head)
		*(.text)
		*(.sfpr)
	}
  
	.rodata : {
		__rodata_start = .;
		*(.rodata .rodata.*)
		__rodata_end = .;
	}

	.data : {
		*(.data)
		*(.force.data)
		*(.toc1)
		*(.branch_lt)
	}
 
	. = ALIGN(0x10);
	.opd : {
		*(.opd)
	}
  
	. = ALIGN(0x10);
	.got : {
		__toc_start = . + 0x8000;
		*(.got)
		*(.toc)
	}

	. = ALIGN(0x10);
	.opal_table : {
		__opal_table_start = .;
		KEEP(*(.opal_table))
		__opal_table_end = .;
	}

	/* Do I need to keep these ? */
	.dynsym : { *(.dynsym)	}
	.dynstr : { *(.dynstr)	}

	/* Relocations */
	. = ALIGN(0x10);
	.dynamic : {
		__dynamic_start = .;
		*(.dynamic)
		__dynamic_end = .;
	}

	. = ALIGN(0x10);
	.rela.dyn : {
		__rela_dyn_start = .;
		*(.rela*)
		__rela_dyn_end = .;
	}

	.hash   : { *(.hash)   }
	.interp : { *(.interp) }
	.dynsym : { *(.dynsym) }
	.dynstr : { *(.dynstr) }

	. = ALIGN(0x1000);
	_sbss = .;
	.bss : {
		*(.bss)
	}
	. = ALIGN(0x10000);
	_ebss = .;
	_end = .;

	/* Discards */
	/DISCARD/ : {
		*(.comment)
	}
}
