#pragma once
#include "stdfax.hpp"

namespace hooks
{
	veh_entry image_fn{};

	long map_image( PCONTEXT context )
	{
		dbg::dbg_print("[EACMapper] Handling `SetupEasyAntiCheatModule` hook!");

		auto image_size =
			*reinterpret_cast< std::uint32_t* >( context->Esp + 0x18 );

		const auto image_base =
			reinterpret_cast<void*>( *reinterpret_cast< std::uint32_t* >( context->Esp + 0x14 ) );

		dbg::dbg_print("[EACMapper] Image Size 0x%x", image_size);
		dbg::dbg_print("[EACMapper] Image Base: 0x%x", image_base);

		const auto new_buffer =
			reinterpret_cast<std::uint8_t*>(
				VirtualAlloc(nullptr, 0x1000 * 2048, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));

		if (!new_buffer)
			return EXCEPTION_CONTINUE_EXECUTION;

		memcpy( new_buffer, image_base, image_size );

		utils::decrypt_module(new_buffer, image_size);

		{

			const auto internal_header = static_cast<PIMAGE_NT_HEADERS64>(utils::get_img_header(&image_data[0]));
			const auto image_header = static_cast<PIMAGE_NT_HEADERS64>(utils::get_img_header(new_buffer));

			const auto image_scn_cnt = image_header->FileHeader.NumberOfSections;
			const auto image_hijack_header = &IMAGE_FIRST_SECTION64(image_header)[image_scn_cnt - 1]; // last section = .reloc

			{
				// .reloc isn't executable by default
				image_hijack_header->Characteristics |= (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_WRITE);
				image_hijack_header->Characteristics &= ~IMAGE_SCN_MEM_DISCARDABLE;
			}

			const auto internal_scn_cnt = internal_header->FileHeader.NumberOfSections;
			const auto internal_scn_header = IMAGE_FIRST_SECTION64(internal_header);
			const auto initial_size = image_hijack_header->SizeOfRawData;

			memcpy(&new_buffer[image_size], &new_buffer[image_hijack_header->PointerToRawData], image_hijack_header->SizeOfRawData);
			image_hijack_header->PointerToRawData = image_size;

			std::uint8_t hook_buffer[] =
			{
				0xE9, 0x00, 0x00, 0x00, 0x00
			};

			const auto oep_buffer = reinterpret_cast<std::uint8_t*>( utils::find_export_raw( image_data, "?entry_buffer" ) );
			const auto entry_rva = reinterpret_cast<std::uint8_t*>( utils::find_export_raw( image_data, "?entry_rva" ) );
			const auto raw_oep = utils::get_raw_address( new_buffer, image_header->OptionalHeader.AddressOfEntryPoint, image_header );

			memcpy(oep_buffer, raw_oep, sizeof( hook_buffer ) );
			memcpy(entry_rva, &image_header->OptionalHeader.AddressOfEntryPoint, sizeof( std::uint32_t ) );

			*reinterpret_cast<std::uint32_t*>(&hook_buffer[1]) = ((image_header->OptionalHeader.SizeOfImage - image_header->OptionalHeader.AddressOfEntryPoint) + ((internal_header->OptionalHeader.AddressOfEntryPoint + initial_size) - (internal_scn_header->VirtualAddress)) - 5);
			memcpy( raw_oep, hook_buffer, sizeof( hook_buffer ) );

			for (auto i = 0U; i < internal_scn_cnt; ++i)
			{
				const auto internal_scn = &internal_scn_header[i];
				const auto data_base = &new_buffer[image_size] + initial_size;
				memcpy(&data_base[internal_scn->VirtualAddress], &image_data[internal_scn->PointerToRawData], internal_scn->SizeOfRawData);

				dbg::dbg_print("[EACMapper] Mapped Section: %s!", &internal_scn->Name[0]);
			}

			const auto real_size = internal_header->OptionalHeader.SizeOfImage - internal_scn_header->VirtualAddress;

			{
				image_header->OptionalHeader.SizeOfImage += real_size;
				image_hijack_header->Misc.VirtualSize += real_size;
				image_hijack_header->SizeOfRawData += real_size;
				image_size += real_size;
			}
		}

		utils::encrypt_module(new_buffer, image_size);

		// Overwrite the caller's stack with the modified parameters.
		*reinterpret_cast<std::uint32_t*>( context->Esp + 0x18 ) = image_size;
		*reinterpret_cast<std::uint8_t**>( context->Esp + 0x14 ) = new_buffer;

		std::uint32_t protect;
		const auto instruction_pointer = reinterpret_cast<void*>( context->Eip );

		{
			VirtualProtect( instruction_pointer, sizeof( std::uint8_t ), PAGE_EXECUTE_READWRITE, &protect );
			*reinterpret_cast<std::uint8_t*>( instruction_pointer ) = image_fn.original;
			VirtualProtect( instruction_pointer, sizeof( std::uint8_t ), protect, &protect );
		}

		return EXCEPTION_CONTINUE_EXECUTION;
	}
}