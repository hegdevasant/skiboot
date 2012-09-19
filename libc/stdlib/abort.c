/******************************************************************************
 * Copyright (c) 2004, 2008, 2012 IBM Corporation
 * All rights reserved.
 * This program and the accompanying materials
 * are made available under the terms of the BSD License
 * which accompanies this distribution, and is available at
 * http://www.opensource.org/licenses/bsd-license.php
 *
 * Contributors:
 *     IBM Corporation - initial implementation
 *****************************************************************************/

#include <stdlib.h>
#include <stdio.h>

void abort(void)
{
	fputs(stderr, "Aborting!\n");
	for (;;);
}

void assert_fail(const char *msg)
{
	fputs(stderr, "Assert fail:");
	fputs(stderr, msg);
	fputs(stderr, "\n");
	abort();
}
