#pragma once

#include <vector>
#include <Zydis/Zydis.h>
#include "pubg.h"

namespace dump 
{
	bool set_static_offsets(const ZydisDecoder& decoder, const uintptr_t start, const uintptr_t end);
	bool set_object_decrytors(const ZydisDecoder& decoder, const uintptr_t start, const uintptr_t end);
	pubg::UObject find_object(const char* outer_name, const char* var_name);
	void dump(const uintptr_t start, const uintptr_t end);
}