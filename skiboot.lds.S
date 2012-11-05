ENTRY(boot_entry);
SECTIONS
{
	. = 0;

 	.text : {
		*(.head)
		*(.text)
		*(.sfpr)
	}
  
	.rodata : {
		__rodata_start = .;
		*(.rodata)
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
