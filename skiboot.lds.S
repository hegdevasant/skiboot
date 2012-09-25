ENTRY(__entry);
SECTIONS
{
	. = 0;

 	.text : {
		*(.head)
		*(.text)
		*(.sfpr)
	}
  
	.rodata : {
		*(.rodata)
	}

	.data : {
		*(.data)
		*(.force.data)
		*(.toc1)
		*(.branch_lt)
	}
 
	. = ALIGN(0x1000);

	.opd : {
		*(.opd)
	}
  
	.got : {
		__toc_start = . + 0x8000;
		*(.got)
		*(.toc)
	}

	/* Do I need to keep these ? */
	.dynsym : { *(.dynsym)	}
	.dynstr : { *(.dynstr)	}

	/* Relocations */
	.dynamic : {
		__dynamic_start = .;
		*(.dynamic)
		__dynamic_end = .;
	}

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
