/******************************************************************************
 * Copyright (c) 2004, 2008 IBM Corporation
 * All rights reserved.
 * This program and the accompanying materials
 * are made available under the terms of the BSD License
 * which accompanies this distribution, and is available at
 * http://www.opensource.org/licenses/bsd-license.php
 *
 * Contributors:
 *     IBM Corporation - initial implementation
 *****************************************************************************/


#include "stdio.h"
#include "string.h"
#include "unistd.h"


int fputs(FILE *stream, char *str)
{
	int ret;

	ret = write(stream->fd, str, strlen(str));
	write(stream->fd, "\r\n", 2);

	return ret;
}

