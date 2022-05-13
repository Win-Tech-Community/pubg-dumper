#include "dump.h"
#include "displacement.h"
#include "utils.h"

uint64_t displacement::XenuineDecrypt = 0;
uint64_t displacement::FName::Names = 0;
uint64_t displacement::FName::ElementsPerChunk = 0;
uint64_t displacement::Offset = 0;
uint64_t displacement::Func = 0;
uint64_t displacement::GUObjectArray = 0;
uint64_t displacement::GWorld = 0;

pubg::Decryptor64 class_decryptor{};
pubg::Decryptor64 outer_decryptor{};
pubg::Decryptor32 name_index_decryptor{};
pubg::Decryptor32 name_number_decryptor{};
pubg::FNameTable name_table{};
pubg::FUObjectArray object_array{};
pubg::TUObjectArray obj_objects{};

void print8(const char* var_name, uint32_t offset)
{
	printf("constexpr uint32_t %s = 0x%08X;\n", var_name, offset);
}

void print4(const char* var_name, uint32_t offset)
{
	printf("constexpr uint32_t %s = 0x%04X;\n", var_name, offset);
}

void print4(const char* outer_name, const char* var_name)
{
	printf("constexpr uint32_t %s = 0x%04X;\n", var_name, dump::find_object(outer_name, var_name).GetOffset());
}

bool dump::set_static_offsets(const ZydisDecoder& decoder, const uintptr_t start, const uintptr_t end) 
{
	auto in_range = [&start, &end](uintptr_t addr)
	{
		return addr > start && addr < start + end;
	};

	// GWorld, XenuineDecrypt
	for (size_t i = 0; i < 5 && !displacement::XenuineDecrypt && !displacement::GWorld; ++i)
	{
		uintptr_t target_address = utils::find_string_reference_lea(decoder, start, end, "r.OneFrameThreadLag", i);

		std::vector<uintptr_t>scan = utils::find_pattern(
			target_address - 0x1000, target_address,
			"\xE8\x00\x00\x00\x00\x48\x8B\xD8\x48\x85\xC0", "x????xxxxxx");

		if (!scan.size())
			continue;

		uintptr_t func = utils::calc_relative(scan.front() + 1);

		scan = utils::find_pattern(
			func, func + 0x100,
			"\x48\xFF\x25", "xxx"); // jmp qword ptr []

		displacement::XenuineDecrypt = utils::calc_relative(scan[0] + 3) - start;

		scan = utils::find_pattern(
			func, func + 0x100,
			"\x8B", "x");

		displacement::GWorld = utils::calc_relative(scan[0] + 2) - start;

		print8("XenuineDecrypt", displacement::XenuineDecrypt);
		print8("GWorld", displacement::GWorld);

		pubg::xe_init(displacement::XenuineDecrypt);
	}

	// Names, ElementsPerChunk
	{
		std::vector<uintptr_t> scan = utils::find_pattern(
			start, end,
			"\x48\x8B\x15\x00\x00\x00\x00\xB9\x00\x00\x00\x00\xFF\x15\x00\x00\x00\x00\x48\x8B\x0D", "xxx????x????xx????xxx");

		displacement::FName::Names = utils::calc_relative(scan[0] + 3) - start;

		scan = utils::find_pattern(
			start, end,
			"\x69\xc7\x00\x00\x00\x00\x44\x8b\xf3", "xx????xxx");

		displacement::FName::ElementsPerChunk = *(uint32_t*)(scan[0] + 2);

		printf("namespace FName\n");
		printf("{\n");
		print8("Names", displacement::FName::Names);
		print4("ElementsPerChunk", displacement::FName::ElementsPerChunk);
		printf("}\n");

		uintptr_t names_ptr = 0;

		names_ptr = *(pubg::EncryptedObjectPtr<uintptr_t>*)(displacement::FName::Names + start);
		names_ptr = process::rpm<pubg::EncryptedObjectPtr<uintptr_t>>((void*)names_ptr);
		names_ptr = process::rpm<pubg::EncryptedObjectPtr<uintptr_t>>((void*)names_ptr);

		process::rpm((void*)names_ptr, &name_table, sizeof(name_table));
	}

	// GUObjectArray
	{
		uintptr_t target_address = utils::find_string_reference_lea(decoder, start, end, "SHOWDEFAULTS", 0), result = 0;

		std::vector<uintptr_t> scan = utils::find_pattern(
			target_address, target_address + 0x1000000,
			"\x0f\x8d", "xx");

		for (uintptr_t& i : scan) 
		{
			result = utils::calc_relative(i + 9);

			if ((result & 0xF) != 0x8)
				continue;

			if (in_range(result))
			{
				result -= start;
				break;
			}
		}

		displacement::GUObjectArray = result - 0x18;
		print8("GUObjectArray", displacement::GUObjectArray);

		object_array = *(pubg::FUObjectArray*)(start + displacement::GUObjectArray);
		obj_objects = object_array.ObjObjects;
	}

	return in_range(displacement::XenuineDecrypt + start)
		&& in_range(displacement::GWorld + start)
		&& in_range(displacement::FName::Names + start) 
		&& in_range(displacement::GUObjectArray + start);
}

bool dump::set_object_decrytors(const ZydisDecoder& decoder, const uintptr_t start, const uintptr_t end)
{
	uintptr_t target_address = utils::find_string_reference_lea(decoder, start, end, "Failed to find %s %s in %s", 0);

	ZyanU8* decode_start = (ZyanU8*)target_address - 0x200;
	ZyanU8* decode_end = (ZyanU8*)target_address;
	ZyanU8* curr_addr = decode_start;

	std::vector<ZydisDecodedInstruction> decoded;
	size_t shl_x20_count = 0;

	while (curr_addr < decode_end)
	{
		ZydisDecodedInstruction instruction;

		if (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, (void*)curr_addr, INT_MAX, &instruction)))
		{
			decoded.push_back(instruction);
			curr_addr += instruction.length;

			if (instruction.mnemonic == ZYDIS_MNEMONIC_SHL)
			{
				if (instruction.operands[1].imm.value.u == 0x20)
					++shl_x20_count;
			}
		}
		else
		{
			++curr_addr;
		}
	}

	size_t shl_skip = shl_x20_count - 2;
	size_t shl_count = 0;

	for (size_t i = 0; i < decoded.size(); ++i) 
	{
		switch (decoded[i].mnemonic)
		{
		case ZYDIS_MNEMONIC_SHL:
			if (!(decoded[i].operands[1].imm.value.u == 0x20 || decoded[i].operands[1].imm.value.u == 0x10))
				continue;
			if (shl_count == 0 + shl_skip)
				utils::set_x64_decryptor(decoded, i, outer_decryptor);
			else if (shl_count == 1 + shl_skip)
				utils::set_x64_decryptor(decoded, i, class_decryptor);
			else if (shl_count == 3 + shl_skip)
				utils::set_fname_decryptor(decoded, i, name_index_decryptor, name_number_decryptor);
			++shl_count;
			break;
		default:
			break;
		}
	}

	if (!outer_decryptor.is_valid())
	{
		uintptr_t _target_address = (uintptr_t)decode_end;
		while (*(uint64_t*)++_target_address != outer_decryptor.xor_key_2) {}

		memset(&outer_decryptor, 0, sizeof(outer_decryptor));

		std::vector<ZydisDecodedInstruction> _decoded;

		ZyanU8* _decode_start = (ZyanU8*)_target_address - 50;
		ZyanU8* _decode_end = (ZyanU8*)_target_address + 50;
		ZyanU8* _curr_addr = _decode_start;

		while (_curr_addr < _decode_end)
		{
			ZydisDecodedInstruction instruction;

			if (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, (void*)_curr_addr, INT_MAX, &instruction)))
			{
				_decoded.push_back(instruction);
				_curr_addr += instruction.length;
			}
			else
			{
				++_curr_addr;
			}
		}

		for (size_t x = 0; x < _decoded.size(); ++x) 
		{
			if (_decoded[x].mnemonic == ZYDIS_MNEMONIC_SHL) 
			{
				utils::set_x64_decryptor(_decoded, x, outer_decryptor);
				break;
			}
		}
	}

	return outer_decryptor.is_valid() 
		&& class_decryptor.is_valid()
		&& name_index_decryptor.is_valid() 
		&& name_number_decryptor.is_valid();
}

pubg::UObject dump::find_object(const char* outer_name, const char* var_name) 
{
	if (!obj_objects.Objects) return {};

	for (uint32_t i = 0; i < object_array.NumElements; ++i) 
	{
		pubg::FUObjectItem item;
		process::rpm((void*)(obj_objects.Objects + i * sizeof(pubg::FUObjectItem) + 8), &item, sizeof(item));
		if (!item.Object) continue;

		pubg::UObject obj;
		process::rpm((void*)item.Object, &obj, sizeof(obj));
		if (!obj.GetClass(class_decryptor) || !obj.GetOuter(outer_decryptor)) continue;

		pubg::FNameEntry obj_name;
		pubg::get_name_entry(&name_table, obj.GetFName(name_index_decryptor, name_number_decryptor).ComparisonIndex, &obj_name);
		if (strcmp(obj_name.AnsiName, var_name))  continue;

		pubg::UObject obj_outer;
		process::rpm(obj.GetOuter(outer_decryptor), &obj_outer, sizeof(obj_outer));

		pubg::FNameEntry obj_outer_name;
		pubg::get_name_entry(&name_table, obj_outer.GetFName(name_index_decryptor, name_number_decryptor).ComparisonIndex, &obj_outer_name);

		if (strcmp(obj_outer_name.AnsiName, outer_name))
			continue;

		return obj;
	}

	return {};
}

void dump::dump(const uintptr_t start, const uintptr_t end)
{
	// UProperty Offset
	{
		pubg::UObject obj = find_object("Player", "CurrentNetSpeed");

		for (uint32_t i = 0; i <= 0x100; i += 0x4) 
		{
			uint32_t current = *(uint32_t*)(obj.buf + i);

			if (current >= 0x30 && current <= 0x50)
			{
				displacement::Offset = i;
				break;
			}
		}
	}

	// UFunction Func
	{
		pubg::UObject obj = find_object("SceneComponent", "K2_GetComponentRotation");

		for (uint32_t i = 0x100; i <= 0x200; i += 0x8) 
		{
			uintptr_t current = *(uintptr_t*)(obj.buf + i);

			if (current - process::image_base < process::image_size)
			{
				current = current - process::image_base + start;

				std::vector<uintptr_t>scan = utils::find_pattern(
					current, current + 0x50,
					"\x0F\x10", "xx");

				if (scan.size() > 1) 
				{
					displacement::Func = i;
					break;
				}
			}
		}
	}

	auto world = *(pubg::EncryptedObjectPtr<uintptr_t>*)(start + displacement::GWorld);
	auto current_level = process::rpm<pubg::EncryptedObjectPtr<uintptr_t>>((void*)(world + find_object("World", "CurrentLevel").GetOffset()));

	for (uint32_t i = 0; i <= 0x1000; i += 8) 
	{
		auto game_instance = process::rpm<pubg::EncryptedObjectPtr<uintptr_t>>((void*)(world + i));

		for (uint32_t j = 0; j <= 0x100; j += 8) 
		{
			auto local_players = process::rpm<pubg::TArray<pubg::EncryptedObjectPtr<uintptr_t>>>((void*)(game_instance + j));

			if (local_players.IsValid() && local_players.Num() == 1) 
			{
				pubg::UObject obj;
				process::rpm((void*)(uintptr_t)local_players.GetVector()[0], &obj, sizeof(obj));
				if (!obj.GetClass(class_decryptor) || !obj.GetOuter(outer_decryptor)) continue;

				pubg::FNameEntry obj_name;
				pubg::get_name_entry(&name_table, obj.GetFName(name_index_decryptor, name_number_decryptor).ComparisonIndex, &obj_name);

				//if (!strcmp(obj_name.AnsiName, "TslLocalPlayer")) 
				{
					print4("GameInstance", i);
					print4("LocalPlayers", j);
				}
			}
		}
	}

	size_t cnt = 0;

	for (uint32_t i = 0; i < 0x500; i += 8)
	{
		uintptr_t current = pubg::xe_decrypt(process::rpm<uintptr_t>((void*)(current_level + i)));
		auto actor_array = process::rpm<pubg::TArray<uintptr_t>>((void*)current);
		if (!actor_array.IsValid()) continue;

		pubg::UObject obj;
		process::rpm((void*)actor_array.GetVector()[0], &obj, sizeof(obj));
		if (!obj.GetClass(class_decryptor) || !obj.GetOuter(outer_decryptor)) continue;

		pubg::FNameEntry obj_name;
		pubg::get_name_entry(&name_table, obj.GetFName(name_index_decryptor, name_number_decryptor).ComparisonIndex, &obj_name);

		if (utils::is_valid_entry(obj_name.AnsiName)) 
		{
			if (cnt == 0)
			{
				print4("Actors", i);
			}
			else
			{
				print4("ActorsForGC", i);
				break;
			}

			++cnt;
		}
	}

	{
		uintptr_t func = find_object("Actor", "IsOverlappingActor").GetFunction() - process::image_base + start;
		//printf("//Found Actor.IsOverlappingActor %p\n", func);

		std::vector<uintptr_t> call = utils::find_pattern(
			func, func + 0x100,
			"\xE8", "x");

		func = utils::calc_relative(call[1] + 1);

		std::vector<uintptr_t>scan = utils::find_pattern(
			func, func + 0x100,
			"\x48\x00\x00\x00\x00\x00\x00", "x????xx");

		print4("OwnedComponents", *(uint32_t*)(scan[0] + 3));
	}

	{
		uintptr_t func = find_object("TslSettings", "GetTslSettings").GetFunction() - process::image_base + start;
		//printf("//Found TslSettings.GetTslSettings %p\n", func);

		std::vector<uintptr_t> call = utils::find_pattern(
			func, func + 0x100,
			"\xE8", "x");

		{
			uintptr_t func = utils::calc_relative(call[0] + 1);

			std::vector<uintptr_t>scan =
				utils::find_pattern(func, func + 0x100,
					"\x48\x83\x3D\x00\x00\x00\x00\x00", "xxx????x");

			print8("TslSettingsBase", utils::calc_relative(scan[0] + 3, 5) - start);
		}

		{
			uintptr_t func = utils::calc_relative(call[1] + 1);

			std::vector<uintptr_t>scan =
				utils::find_pattern(func, func + 0x100,
					"\x48\x8B\x81\x00\x00\x00\x00", "xxx??xx");

			print4("TslSettings", *(uint32_t*)(scan[0] + 3));
		}
	}

	{
		uintptr_t func = find_object("SceneComponent", "K2_GetComponentToWorld").GetFunction() - process::image_base + start;
		//printf("//Found SceneComponent.K2_GetComponentToWorld %p\n", func);

		std::vector<uintptr_t>scan = utils::find_pattern(
			func, func + 0x100, 
			"\x0F\x10", "xx");

		print4("ComponentToWorld", *(uint32_t*)(scan[0] + 3));
	}

	{
		uintptr_t func = find_object("SceneComponent", "K2_GetComponentRotation").GetFunction() - process::image_base + start;
		//printf("//Found SceneComponent.K2_GetComponentRotation %p\n", func);

		std::vector<uintptr_t>scan = utils::find_pattern(
			func, func + 0x100,
			"\xF2", "x");

		print4("ComponentRotation", *(uint32_t*)(scan[1] + 5));
	}

	{
		uintptr_t func = find_object("SceneComponent", "K2_GetComponentLocation").GetFunction() - process::image_base + start;
		//printf("//Found SceneComponent.K2_GetComponentLocation %p\n", func);

		std::vector<uintptr_t>scan = utils::find_pattern(func, func + 0x100,
			"\x0F\x10", "xx");

		print4("ComponentLocation", *(uint32_t*)(scan[0] + 3));
	}


	{
		uintptr_t func = find_object("Item", "BP_GetItemID").GetFunction() - process::image_base + start;
		//printf("//Found Item.BP_GetItemID %p\n", func);

		std::vector<uintptr_t>scan = utils::find_pattern(func, func + 0x100,
			"\x48\x8B", "xx"); // movr

		print4("ItemID", *(uint32_t*)(scan[1] + 3));
		print4("ItemTable", *(uint32_t*)(scan[0] + 3));
	}

	{
		uintptr_t func = find_object("WeaponProcessorComponent", "GetWeaponIndex").GetFunction() - process::image_base + start;
		//printf("//Found WeaponProcessorComponent.GetWeaponIndex %p\n", func);

		std::vector<uintptr_t>scan = utils::find_pattern(func, func + 0x100,
			"\x0F\xBE", "xx");

		print4("WeaponIndex", *(uint32_t*)(scan[0] + 3));
	}

	{
		uintptr_t func = find_object("TslLivingThing", "GetWorldTimeSeconds").GetFunction() - process::image_base + start;
		//printf("//Found TslLivingThing.GetWorldTimeSeconds %p\n", func);

		std::vector<uintptr_t> call = utils::find_pattern(
			func, func + 0x100,
			"\xE8", "x");

		func = utils::calc_relative(call[0] + 1);

		std::vector<uintptr_t>scan = utils::find_pattern(
			func, func + 0x100,
			"\xF3\x0F", "xx");

		print4("TimeSeconds", *(uint32_t*)(scan[0] + 4));
	}

	print4("World", "CurrentLevel");

	print4("PlayerController", find_object("Player", "CurrentNetSpeed").GetOffset() - 0x8);
	print4("PlayerController", "AcknowledgedPawn");
	print4("PlayerController", "SpectatorPawn");
	print4("PlayerController", "PlayerCameraManager");
	print4("PlayerController", "InputYawScale");

	print4("PlayerCameraManager", "CameraCache");
	print4("CameraCacheEntry", "POV");
	print4("MinimalViewInfo", "FOV");
	print4("MinimalViewInfo", "Rotation");
	print4("MinimalViewInfo", "Location");

	print4("Actor", "RootComponent");
	print4("Actor", "ReplicatedMovement");

	print4("Pawn", "PlayerState");

	print4("Character", "Mesh");

	print4("TslSettings", "BallisticDragScale");
	print4("TslSettings", "BallisticDropScale");

	print4("TslCharacter", "Health");
	print4("TslCharacter", "HealthMax");
	print4("TslCharacter", "GroggyHealth");
	print4("TslCharacter", "GroggyHealthMax");
	print4("TslCharacter", "CharacterName");
	print4("TslCharacter", "LastTeamNum");
	print4("TslCharacter", "VehicleRiderComponent");
	print4("TslCharacter", "WeaponProcessor");
	print4("TslCharacter", "SpectatedCount");

	print4("SceneComponent", "ComponentVelocity");
	print4("SceneComponent", "AttachParent");

	print4("PrimitiveComponent", "LastSubmitTime");
	print4("PrimitiveComponent", "LastRenderTimeOnScreen");

	print4("SkeletalMeshComponent", "AnimScriptInstance");
	print4("StaticMeshComponent", "StaticMesh");

	const int32_t DroppedItem_Item = find_object("DroppedItem", "Item").GetOffset();
	print4("DroppedItem_Item", DroppedItem_Item);

	const int32_t DroppedItemInteractionComponent_Item = find_object("DroppedItemInteractionComponent", "Item").GetOffset();
	print4("DroppedItemInteractionComponent_Item", DroppedItemInteractionComponent_Item);

	print4("VehicleRiderComponent", "SeatIndex");
	print4("VehicleRiderComponent", "LastVehiclePawn");

	print4("WeaponProcessorComponent", "EquippedWeapons");

	print4("TslWeapon", "Mesh3P");
	print4("TslWeapon", "FiringAttachPoint");

	const int32_t IronSightZeroingDistances =
		find_object("TslWeapon", "WeaponConfig").GetOffset() +
		find_object("WeaponData", "IronSightZeroingDistances").GetOffset();
	print4("IronSightZeroingDistances", IronSightZeroingDistances);

	print4("TslWeapon_Gun", "bAlwaysUseIronSightZeroing");
	print4("TslWeapon_Gun", "AmmoPerClip");
	print4("TslWeapon_Gun", "CurrentZeroLevel");
	print4("TslWeapon_Gun", "CurrentCantedZeroLevel");
	print4("TslWeapon_Gun", "ScopingAttachPoint");

	print4("TslWeapon_Trajectory", "WeaponTrajectoryData");
	print4("TslWeapon_Trajectory", "TrajectoryGravityZ");

	print4("TslAnimInstance", "ControlRotation_CP");
	print4("TslAnimInstance", "RecoilADSRotation_CP");
	print4("TslAnimInstance", "LeanLeftAlpha_CP");
	print4("TslAnimInstance", "LeanRightAlpha_CP");
	print4("TslAnimInstance", "bIsScoping_CP");
	print4("TslAnimInstance", "bIsReloading_CP");

	print4("WeaponTrajectoryData", "TrajectoryConfig");

	const int32_t ItemPackage_Items = find_object("ItemPackage", "Items").GetOffset();
	print4("ItemPackage_Items", ItemPackage_Items);

	print4("TslPlayerState", "PlayerStatistics");
	print4("TslPlayerState", "DamageDealtOnEnemy");

	print4("CurveVector", "FloatCurves");
}