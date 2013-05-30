/* (C) Copyright IBM Corp., 2013 and provided pursuant to the Technology
 * Licensing Agreement between Google Inc. and International Business
 * Machines Corporation, IBM License Reference Number AA130103030256 and
 * confidentiality governed by the Parties’ Mutual Nondisclosure Agreement
 * number V032404DR, executed by the parties on November 6, 2007, and
 * Supplement V032404DR-3 dated August 16, 2012 (the “NDA”). */
#ifndef __MEM_REGION_MALLOC_H
#define __MEM_REGION_MALLOC_H

#define __loc2(line)    #line
#define __loc(line)	__loc2(line)
#define __location__	__FILE__ ":" __loc(__LINE__)

void *__malloc(size_t size, const char *location);
void *__zalloc(size_t size, const char *location);
void *__realloc(void *ptr, size_t size, const char *location);
void __free(void *ptr, const char *location);
void *__memalign(size_t boundary, size_t size, const char *location);

#define malloc(size) __malloc(size, __location__)
#define zalloc(size) __zalloc(size, __location__)
#define realloc(ptr, size) __realloc(ptr, size, __location__)
#define free(ptr) __free(ptr, __location__)
#define memalign(boundary, size) __memalign(boundary, size, __location__)
#endif /* __MEM_REGION_MALLOC_H */
