#pragma once

#include <windows.h>
#include <string>

#pragma comment(lib, "ntdll.lib")
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

extern "C"
{
	NTSTATUS NTAPI NtReadVirtualMemory(HANDLE, PVOID, PVOID, ULONG, PULONG);
}

namespace process 
{
	extern HANDLE handle;
	extern uintptr_t image_base;
	extern uint32_t image_size;
	extern uint32_t id;
	extern uint8_t* dump;

	bool init(const std::wstring process_name);

	template <typename T>
	T rpm(void* address) 
	{
		T buffer{};
		NT_SUCCESS(NtReadVirtualMemory(handle, (void*)address, &buffer, sizeof(buffer), nullptr));
		return buffer;
	}

	template <typename T>
	bool rpm(void* address, T buffer, size_t size) 
	{
		return NT_SUCCESS(NtReadVirtualMemory(handle, address, buffer, size, nullptr));
	}
}