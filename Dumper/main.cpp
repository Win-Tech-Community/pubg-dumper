#include <Windows.h>
#include <iostream>

#include "process.h"
#include "dump.h"

#include <Zydis/Zydis.h>
#pragma comment(lib, "zydis.lib")

int main()
{
	if (!process::init(L"TslGame.exe")) 
	{
		MessageBoxA(0, "could't find the game", 0, 0);
		return 1;
	}

	ZydisDecoder decoder;
	ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);

	const uintptr_t start = (uintptr_t)process::dump;
	const uintptr_t end = start + process::image_size;

	if (!dump::set_static_offsets(decoder, start, end)) 
	{
		MessageBoxA(0, "error", 0, 0);
		return 1;
	}

	if (!dump::set_object_decrytors(decoder, start, end)) 
	{
		MessageBoxA(0, "error", 0, 0);
		return 1;
	}

	dump::dump(start, end);

	return 0;
}