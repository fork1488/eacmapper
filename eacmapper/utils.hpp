#pragma once
#include "stdfax.hpp"

namespace utils
{

	void* get_img_header( const void* image_base ) 
	{
		const auto dos_header = 
			reinterpret_cast< PIMAGE_DOS_HEADER >( const_cast< void* >( image_base ) );

		// NT header varies between x86/x64 however the IMAGE_DOS_HEADER structure remains unchanged.
		const auto nt_header =
			reinterpret_cast<void*>( 
				reinterpret_cast<std::uint8_t*>( const_cast< void* >( image_base ) ) + dos_header->e_lfanew );

		return nt_header;
	}

	void decrypt_module( std::uint8_t* module_base, const std::uint32_t module_size )
	{
		std::uint32_t new_size = module_size - 2;
		module_base[ module_size - 1 ] += 3 - 3 * module_size;

		while ( new_size )
		{
			module_base[ new_size ] += -3 * new_size - module_base[ new_size + 1 ];
			--new_size;
		}

		module_base[ 0 ] -= module_base[ 1 ];
	}

	void encrypt_module( std::uint8_t* module_base, const std::uint32_t module_size )
	{
		std::uint32_t new_size = 0;
		module_base[ module_size - 1 ] += 3 - 3 * module_size;

		while (new_size < module_size)
		{
			module_base[ new_size ] -= -3 * new_size - module_base[ new_size + 1 ];
			++new_size;
		}
	}

	void* find_pattern(const std::uint8_t* image_base, const std::uint32_t image_size, 
		const std::uint8_t* signature, std::uint32_t sig_len, std::uint16_t wildcard )
	{
		const auto check_mask = [&]( const std::uint8_t* start )
		{
			for (auto i = 0UL; i < sig_len; ++i)
			{
				if (start[ i ] != signature[ i ] && signature[ i ] != wildcard)
					return false;
			}

			return true;
		};

		for (auto u = 0UL; u < image_size - sig_len; ++u)
		{
			const auto scan_start = &image_base[ u ];
			if ( check_mask( scan_start ) )
				return const_cast<std::uint8_t*>( scan_start );
		}

		return nullptr;
	}

	void* get_raw_address( void* image_base, std::uint32_t virtual_rva, PIMAGE_NT_HEADERS64 image_header ) 
	{
		if ( !image_base || !virtual_rva || !image_header )
			return nullptr;

		const auto section_header = IMAGE_FIRST_SECTION(image_header);
		for (auto i = 0U; i < image_header->FileHeader.NumberOfSections; ++i)
		{
			const auto& current_section = &section_header[i];
			if (virtual_rva >= current_section->VirtualAddress && virtual_rva <= static_cast<std::uint64_t>(current_section->VirtualAddress) + current_section->Misc.VirtualSize)
			{
				// convert VirtualAddress to RawData RVA
				return reinterpret_cast<std::uint8_t*>(image_base) + current_section->PointerToRawData + (virtual_rva - current_section->VirtualAddress);
			}
		}

		return nullptr;
	}

	void* find_export_raw( void* image_base, const char* export_name )
	{
		const auto nt_header = static_cast< PIMAGE_NT_HEADERS64 >( utils::get_img_header( image_base ) );
		if (!nt_header)
			return nullptr;

		const auto export_data = nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		const auto export_table = static_cast<IMAGE_EXPORT_DIRECTORY*>( get_raw_address( image_base, export_data, nt_header ) );
		const auto function_table = static_cast<std::uint32_t*>( get_raw_address( image_base, export_table->AddressOfFunctions, nt_header ) );
		const auto ordinal_table = static_cast<std::uint16_t*>( get_raw_address( image_base, export_table->AddressOfNameOrdinals, nt_header ) );
		const auto name_table = static_cast<std::uint32_t*>( get_raw_address( image_base, export_table->AddressOfNames, nt_header ) );

		for (auto i = 0U; i < export_table->NumberOfFunctions; ++i)
		{
			const auto name_entry = static_cast<char*>( get_raw_address( image_base, name_table[ i ], nt_header ) );
			const auto func_entry = get_raw_address( image_base, function_table[ ordinal_table[ i ] ], nt_header );

			if ( strstr( name_entry, const_cast<char*>( export_name ) ) )
				return func_entry;
		}

		return nullptr;
	}

}