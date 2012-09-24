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
 
	. = ALIGN(0x1000);
	_sbss = .;
	.bss : {
		*(.bss)
	}
	. = ALIGN(0x10000);
	_ebss = .;
	_end = .;

	.comment 0 : { *(.comments) }
}
