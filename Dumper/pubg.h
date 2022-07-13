#pragma once

#include <vector>

#include "process.h"
#include "displacement.h"

#define NAME_SIZE 1024
#define NAME_SIZE_SHORT 64
#define NAME_WIDE_MASK 0x1
#define NAME_INDEX_SHIFT 1

namespace pubg 
{
	extern uint8_t* xe_decrypt_container;
	bool xe_init(const uint64_t offset);
	uintptr_t xe_decrypt(const uintptr_t encrypted);

	struct FNameTable;
	struct FNameEntry;

	bool get_name_entry(FNameTable* table, int32_t index, FNameEntry* result);

	template <typename T>
	struct Decryptor 
	{
		static_assert(std::is_same<T, uint32_t>::value | std::is_same<T, uint64_t>::value, "Type error.");

		bool ror;

		T xor_key_1;
		T xor_key_2;

		uint8_t rval;
		uint8_t sval;
		uint8_t offset;

		bool is_valid() const 
		{
			return xor_key_1 && xor_key_2 && rval && sval && offset;
		}

		T decrypt(T encrypted) const
		{
			T result = T{};

			if (std::is_same<T, uint64_t>::value)
				result = ror ? _rotr64(encrypted ^ xor_key_1, rval) : _rotl64(encrypted ^ xor_key_1, rval);
			else 
				result = ror ? _rotr(encrypted ^ xor_key_1, rval) : _rotl(encrypted ^ xor_key_1, rval);

			return result ^ (result << sval) ^ xor_key_2;
		}
	};

	using Decryptor32 = Decryptor<uint32_t>;
	using Decryptor64 = Decryptor<uint64_t>;

	template<typename T>
	struct EncryptedObjectPtr 
	{
		uintptr_t encrypted_address;

		operator uintptr_t() const 
		{ 
			return xe_decrypt(encrypted_address);
		}

		template<typename U = T>
		bool read(U* buffer) const
		{
			bool status = process::rpm((void*)xe_decrypt(encrypted_address), &buffer, sizeof(U));
			return status;
		}
	};

	template<typename T>
	struct ObjectPtr 
	{
		uintptr_t address;

		operator uintptr_t() const
		{ 
			return address;
		}

		template<typename U = T>
		bool read(U* buffer) const 
		{
			bool status = process::rpm((void*)address, &buffer, sizeof(U));
			return status;
		}
	};

	template<typename T>
	struct EncryptedObject 
	{
		uint64_t encrypted_obj;

		operator T() const 
		{ 
			return (T)xe_decrypt(encrypted_obj);
		}
	};

	struct FName
	{
		uint32_t ComparisonIndex;
		uint32_t Number;
	};

	struct FNameTable
	{
		EncryptedObject<uint64_t>Chunks;
		EncryptedObject<uint64_t> NumElements;
		EncryptedObject<uint64_t> NumChunks;
	};

	struct FNameEntry
	{
	public:
		int32_t GetIndex() const 
		{
			const auto index = GetIndexInternal();
			return (index >> NAME_INDEX_SHIFT);
		}

		bool IsWide() const 
		{
			const auto index = GetIndexInternal();
			return (index & NAME_WIDE_MASK);
		}

		int32_t GetNameLength() const 
		{
			if (IsWide()) return (int32_t)wcslen(WideName);
			else return (int32_t)strlen(AnsiName);
		}
	protected:
		int32_t GetIndexInternal() const 
		{
			return int32_t(xe_decrypt(Index));
		}

	public:
		uint64_t Index = 0;
		FNameEntry* HashNext = nullptr;
		union
		{
			char AnsiName[NAME_SIZE];
			wchar_t WideName[NAME_SIZE];
		};
	};

	struct FNameEntryShort
	{
		int32_t Index;
		FNameEntry* HashNext;
		union 
		{
			char AnsiName[NAME_SIZE_SHORT];
			wchar_t WideName[NAME_SIZE_SHORT];
		};
	};

	struct UObject
	{
	public:
		UObject* GetClass(const Decryptor64& decryptor) const
		{
			const auto encrypted = *(uintptr_t*)(buf + decryptor.offset);
			return (UObject*)decryptor.decrypt(encrypted);
		}

		FName GetFName(const Decryptor32& name_index_decryptor, const Decryptor32& nmae_number_decryptor) const
		{
			auto temp = *(FName*)(buf + name_index_decryptor.offset);

			temp.ComparisonIndex = name_index_decryptor.decrypt(temp.ComparisonIndex);
			temp.Number = name_index_decryptor.decrypt(temp.Number);

			return temp;
		}

		UObject* GetOuter(const Decryptor64& decryptor) const
		{
			const auto encrypted = *(uintptr_t*)(buf + decryptor.offset);
			return (UObject*)decryptor.decrypt(encrypted);
		}

		int32_t GetOffset() const 
		{
			return *(int32_t*)(buf + displacement::Offset);
		}

		uintptr_t GetFunction() const 
		{
			return *(uintptr_t*)(buf + displacement::Func);
		}
	public:
		uint8_t buf[0x200];
	};

	struct FUObjectItem 
	{
		uintptr_t Object;
		uintptr_t pad[2];
	};

	struct TUObjectArray 
	{
		EncryptedObject<uint64_t> Objects;
	};

	struct FUObjectArray 
	{
		TUObjectArray ObjObjects;
		EncryptedObject<uint64_t> MaxElements;
		uint32_t NumElements;
	};

	template<class T>
	class TArray
	{
	private:
		uintptr_t Data;
		uint32_t Count;
	public:
		operator uintptr_t() 
		{ 
			return Data; 
		}

		bool IsValid() const
		{
			if (!Count || Count > 0x100000)
				return false;

			BYTE byte;
			return process::rpm((void*)Data, &byte, sizeof(byte));
		}

		uint32_t Num() const
		{
			return Count;
		}

		std::vector<T> GetVector() const
		{
			std::vector<T> vector(Count);
			process::rpm((void*)Data, &vector[0], sizeof(T) * Count);
			return vector;
		}
	};

}