#include "pubg.h"

uint8_t* pubg::xe_decrypt_container = (uint8_t*)VirtualAlloc(nullptr, 0x100, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

bool pubg::xe_init(const uint64_t offset) 
{
	const uintptr_t decrypt_ptr = *(uintptr_t*)(process::dump + offset);
	if (!decrypt_ptr) 
		return false;

	uint8_t backup_bytes[0x100];

	process::rpm((void*)decrypt_ptr, backup_bytes, sizeof(backup_bytes));

	*(uint16_t*)(xe_decrypt_container + 0x0) = static_cast<uint16_t>(0xB848);
	*(uintptr_t*)(xe_decrypt_container + 0x2) = decrypt_ptr + process::rpm<int32_t>((void*)(decrypt_ptr + 0x3)) + 7;

	memcpy(&xe_decrypt_container[0xA], &backup_bytes[0x7], 0x100 - 0xA);
}

uintptr_t pubg::xe_decrypt(const uintptr_t encrypted)
{
	typedef uintptr_t(__fastcall* xe_decrypt_fn_t)(uint64_t, uintptr_t);
	return xe_decrypt_fn_t(xe_decrypt_container)(0, encrypted);
}

bool pubg::get_name_entry(FNameTable* table, int32_t index, FNameEntry* result)
{
	const int32_t chunk_index = 8 * (index / displacement::FName::ElementsPerChunk);
	const int32_t within_chunk_index = 8 * (index % displacement::FName::ElementsPerChunk);

	uintptr_t name_ptr;

	process::rpm((void*)(table->Chunks + chunk_index), &name_ptr, sizeof(name_ptr));

	process::rpm((void*)(name_ptr + within_chunk_index), &name_ptr, sizeof(name_ptr));

	bool status = process::rpm((void*)name_ptr, result, sizeof(FNameEntryShort));

	result->AnsiName[NAME_SIZE_SHORT - 1] = 0;
	return status;
}