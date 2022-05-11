#pragma once

#include <vector>
#include <string>
#include <Zydis/Zydis.h>

#include "pubg.h"

namespace utils 
{
	bool compare_data_utf8(const char* data, const char* mask);
	bool compare_data_utf16(const char* data, const char* mask);
	bool is_valid_entry(const char* str);
	uintptr_t calc_relative(uintptr_t current, int32_t relative = 4);
	uintptr_t find_string_reference_lea(const ZydisDecoder& decoder, const uintptr_t start, const uintptr_t end, const char* target_name, size_t pos = 0);
	std::vector<uintptr_t> find_pattern(const uintptr_t start, const uintptr_t end, const std::basic_string_view<char> pattern, const std::basic_string_view<char> mask);
	void set_x64_decryptor(const std::vector<ZydisDecodedInstruction>& decoded, size_t shl_pos, pubg::Decryptor64& decryptor);
	void set_fname_decryptor(const std::vector<ZydisDecodedInstruction>& decoded, size_t shl_pos, pubg::Decryptor32& name_index_decryptor, pubg::Decryptor32& name_number_decryptor);
}