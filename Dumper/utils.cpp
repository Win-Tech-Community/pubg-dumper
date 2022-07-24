#include "utils.h"

bool utils::compare_data_utf8(const char* data, const char* mask) 
{
	while (*mask) 
	{
		if (*data != *mask)
			return false;
		++data;
		++mask;
	}

	return true;
}

bool utils::compare_data_utf16(const char* data, const char* mask) 
{
	while (*mask) 
	{
		if (*data != *mask)
			return false;
		++++data;
		++mask;
	}

	return true;
}

bool utils::is_valid_entry(const char* str) 
{
	if (!str) 
		return false;
	const size_t len = strlen(str);
	return len > 0 && len < 128;
}

uintptr_t utils::calc_relative(uintptr_t current, int32_t relative) 
{
	return current + *(int32_t*)(current) + relative;
}

uintptr_t utils::find_string_reference_lea(const ZydisDecoder& decoder, const uintptr_t start, const uintptr_t end, const char* target_name, size_t pos) 
{
	size_t cnt = 0;

	for (uintptr_t i = 0; i < end - start; ++i)
	{
		ZydisDecodedInstruction instruction;
		if (!ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, (void*)(start + i), INT_MAX, &instruction)))
			continue;

		if (instruction.mnemonic == ZYDIS_MNEMONIC_LEA) 
		{
			uintptr_t reference = (start + i);
			uintptr_t rip = reference + instruction.operands[1].mem.disp.value + instruction.length;

			if (!(rip > start && rip < end))
				continue;

			const char* name = (const char*)rip;
			if (!(compare_data_utf8(name, target_name) || compare_data_utf16(name, target_name)))
				continue;

			if (cnt == pos)
				return reference;

			++cnt;
		}
	}
}

std::vector<uintptr_t> utils::find_pattern(const uintptr_t start, const uintptr_t end, const std::basic_string_view<char> pattern, const std::basic_string_view<char> mask)
{
	std::vector<uintptr_t> result;
	int n = 0;

	for (auto c = start; c < end; ++c) 
	{
		if (mask[n] == '?' || *(uint8_t*)c == (uint8_t)pattern[n])
			++n;
		else
		{
			n = 0;
			if (*(uint8_t*)c == (uint8_t)pattern[0])
				c -= 1;
		}

		if (n >= mask.size())
			result.push_back(c - n + 1);
	}

	return result;
}

/*
TslGame.exe+3FF6082 - 48 8B 47 20           - mov rax,[rdi+20]
TslGame.exe+3FF6086 - 48 BA A3092A6A6DBBECF5 - mov rdx,F5ECBB6D6A2A09A3 { 1781139875 }
TslGame.exe+3FF6090 - 48 33 C2              - xor rax,rdx
TslGame.exe+3FF6093 - 48 C1 C8 12           - ror rax,12 { 18 }
TslGame.exe+3FF6097 - 48 8B D0              - mov rdx,rax
TslGame.exe+3FF609A - 48 C1 E2 20           - shl rdx,20 { 32 } // + 1
TslGame.exe+3FF609E - 49 B8 767E38A5A76C515B - mov r8,5B516CA7A5387E76 { -1523024266 }
TslGame.exe+3FF60A8 - 49 33 D0              - xor rdx,r8
TslGame.exe+3FF60AB - 48 33 D0              - xor rdx,rax
*/

void utils::set_x64_decryptor(const std::vector<ZydisDecodedInstruction>& decoded, size_t shl_pos, pubg::Decryptor64& decryptor)
{
	shl_pos += 1;

	for (size_t i = shl_pos; shl_pos - i < /*7*/10; --i)
	{
		if (decryptor.is_valid())
			break;

		ZydisDecodedInstruction instruction = decoded.at(i);

		switch (instruction.mnemonic)
		{
		case ZYDIS_MNEMONIC_MOV:
			if (!decryptor.xor_key_2)
				decryptor.xor_key_2 = static_cast<uint64_t>(instruction.operands[1].imm.value.u);
			else if (!decryptor.xor_key_1)
				decryptor.xor_key_1 = static_cast<uint64_t>(instruction.operands[1].imm.value.u);
			else if (!decryptor.offset)
				decryptor.offset = instruction.operands[1].mem.disp.value;
			break;
		case ZYDIS_MNEMONIC_SHL:
			if (!decryptor.sval)
				decryptor.sval = instruction.operands[1].imm.value.u;
			break;
		case ZYDIS_MNEMONIC_ROR:
		case ZYDIS_MNEMONIC_ROL:
			decryptor.ror = (instruction.mnemonic == ZYDIS_MNEMONIC_ROR);
			decryptor.rval = instruction.operands[1].imm.value.u;
			break;
		default:
			break;
		}
	}
}

/*
TslGame.exe+3FF610E - 8B 50 34              - mov edx,[rax+34]
TslGame.exe+3FF6111 - 81 F2 1795343B        - xor edx,3B349517 { 0.00 }
TslGame.exe+3FF6117 - 8B 48 30              - mov ecx,[rax+30]
TslGame.exe+3FF611A - 81 F1 B1DB1FF8        - xor ecx,F81FDBB1 { -132129871 }
TslGame.exe+3FF6120 - D1 C9                 - ror ecx,1
TslGame.exe+3FF6122 - 8B C1                 - mov eax,ecx
TslGame.exe+3FF6124 - C1 E0 10              - shl eax,10 { 16 }
TslGame.exe+3FF6127 - 33 C1                 - xor eax,ecx
TslGame.exe+3FF6129 - 35 179523AE           - xor eax,AE239517 { -1373399785 }
TslGame.exe+3FF612E - 89 45 48              - mov [rbp+48],eax // skip
TslGame.exe+3FF6131 - C1 C2 07              - rol edx,07 { 7 }
TslGame.exe+3FF6134 - 8B C2                 - mov eax,edx
TslGame.exe+3FF6136 - C1 E0 10              - shl eax,10 { 16 } // + 2
TslGame.exe+3FF6139 - 33 C2                 - xor eax,edx
TslGame.exe+3FF613B - 35 B1DBAE23           - xor eax,23AEDBB1 { 598662065 }
*/

void utils::set_fname_decryptor(const std::vector<ZydisDecodedInstruction>& decoded, size_t shl_pos, pubg::Decryptor32& name_index_decryptor, pubg::Decryptor32& name_number_decryptor)
{
	shl_pos += 2;

	bool first_disp_ignored = false;

	for (size_t i = shl_pos; shl_pos - i < /*15*/20; --i)
	{
		if ((name_index_decryptor.is_valid() && name_number_decryptor.is_valid()))
			break;

		ZydisDecodedInstruction instruction = decoded.at(i);

		switch (instruction.mnemonic)
		{
		case ZYDIS_MNEMONIC_MOV:
			if (instruction.operands[1].mem.disp.value)
				first_disp_ignored = true;

			if (first_disp_ignored)
			{
				if (!name_index_decryptor.offset)
					name_index_decryptor.offset = instruction.operands[1].mem.disp.value;

				else if (!name_number_decryptor.offset)
					name_number_decryptor.offset = instruction.operands[1].mem.disp.value;
			}
			break;
		case ZYDIS_MNEMONIC_XOR:
			if (!name_number_decryptor.xor_key_2)
				name_number_decryptor.xor_key_2 = static_cast<uint32_t>(instruction.operands[1].imm.value.u);

			else if (!name_index_decryptor.xor_key_2)
				name_index_decryptor.xor_key_2 = static_cast<uint32_t>(instruction.operands[1].imm.value.u);
			else if (!name_index_decryptor.xor_key_1)
				name_index_decryptor.xor_key_1 = static_cast<uint32_t>(instruction.operands[1].imm.value.u);

			else if (!name_number_decryptor.xor_key_1)
				name_number_decryptor.xor_key_1 = static_cast<uint32_t>(instruction.operands[1].imm.value.u);
			break;
		case ZYDIS_MNEMONIC_SHL:
			if (!name_number_decryptor.sval)
				name_number_decryptor.sval = instruction.operands[1].imm.value.u;

			else if (!name_index_decryptor.sval)
				name_index_decryptor.sval = instruction.operands[1].imm.value.u;
			break;
		case ZYDIS_MNEMONIC_ROR:
		case ZYDIS_MNEMONIC_ROL:
			if (!name_number_decryptor.rval) 
			{
				name_number_decryptor.ror = (instruction.mnemonic == ZYDIS_MNEMONIC_ROR);
				name_number_decryptor.rval = instruction.operands[1].imm.value.u;
			}
			else if (!name_index_decryptor.rval)
			{
				name_index_decryptor.ror = (instruction.mnemonic == ZYDIS_MNEMONIC_ROR);
				name_index_decryptor.rval = instruction.operands[1].imm.value.u;
			}
			break;
		default:
			break;
		}
	}
}