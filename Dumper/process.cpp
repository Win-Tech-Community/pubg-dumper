#include "process.h"

#include <TlHelp32.h>
#include <Psapi.h>

HANDLE process::handle = INVALID_HANDLE_VALUE;
uintptr_t process::image_base = 0;
uint32_t process::image_size = 0;
uint32_t process::id = 0;
uint8_t* process::dump = nullptr;

bool process::init(const std::wstring process_name) 
{
	HANDLE snap_shot{ CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
	if (snap_shot == INVALID_HANDLE_VALUE)
		return false;

	PROCESSENTRY32W process_entry{ .dwSize = sizeof(PROCESSENTRY32W) };

	for (Process32FirstW(snap_shot, &process_entry); Process32NextW(snap_shot, &process_entry); )
		if (wcscmp(process_name.data(), process_entry.szExeFile) == NULL)
			id = process_entry.th32ProcessID;

	CloseHandle(snap_shot);

	if (!id || !(handle = OpenProcess(PROCESS_ALL_ACCESS, false, id)))
		return false;

	DWORD cbneeded;

	if (K32EnumProcessModulesEx(handle, (HMODULE*)&image_base, sizeof(image_base), &cbneeded, LIST_MODULES_64BIT))
	{
		IMAGE_DOS_HEADER dos_header = rpm<IMAGE_DOS_HEADER>((void*)image_base);
		IMAGE_NT_HEADERS nt_header = rpm<IMAGE_NT_HEADERS>((void*)(image_base + dos_header.e_lfanew));

		image_size = nt_header.OptionalHeader.SizeOfImage - 0x1000;
		dump = new uint8_t[process::image_size];

		for (uint32_t p = 0; p < image_size; p += 0x1000)
			rpm((void*)(image_base + p), (void*)(dump + p), 0x1000);

		return true;
	}

	return false;
}