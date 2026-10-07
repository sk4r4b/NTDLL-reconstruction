/*
** p4p1: http://p4p1.github.io/
** Created on: Thu 24 Sep 2026 01:46:28 PM CEST
** ntdll_reconstruction.h
** File description:
**  Here is the header for the ntdll reconstruction technique.
*/

#ifndef NTDLL_RECONSTRUCTION_H_
#define NTDLL_RECONSTRUCTION_H_

#include "sk4r4b.h"
#include <windows.h>

#define NTDLL_RECONSTRUCTION_DEPTH 20
#define REPLACE_SIZE 11

// Replace with your own CRT here...
#define ntdll_reconstruction_malloc sk4r4b_malloc
#define ntdll_reconstruction_free sk4r4b_free
#define ntdll_reconstruction_memset sk4r4b_memset
#define ntdll_reconstruction_strncmp sk4r4b_strncmp
#define ntdll_reconstruction_memcmp sk4r4b_memcmp

struct hook_cache {
	unsigned char		*mem;
	void				*ntdll_pos;
	struct hook_cache	*next;
};

struct hook_cache	*ntdll_reconstruction_init(void); // return null if nothing is hooked
struct hook_cache	*ntdll_reconstruction_flip(struct hook_cache *);
void				ntdll_reconstruction_clear_cache(struct hook_cache *);

#endif
