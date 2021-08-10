#include "stdafx.hpp"

__declspec( dllexport ) std::uint8_t entry_buffer[5]; // To be filled by mapper (Original bytes of DllEntryPoint to be restored on execution)
__declspec( dllexport ) std::uint32_t entry_rva; // RVA to the DllEntryPoint filled by mapper.

bool dll_main( const std::uint64_t image_base, const std::uint32_t reason, const void* reserved )
{
	const auto dbg_print = [ ]( const char* msg, ... ) -> void
	{
		va_list args;
		va_start( args, msg );

		char buffer[512];
		mini_vsprintf_s( buffer, sizeof(buffer), msg, args );
		LI_FN( OutputDebugStringA ).get_safe()( buffer );
		return va_end( args );
	};

	dbg_print( "[EACMapper] Image Base: 0x%x", image_base );
	dbg_print( "[EACMapper] DllEntryPoint: 0x%x", entry_rva );

	const auto eac_dll_fn = 
		reinterpret_cast<decltype( &dll_main )>( image_base + entry_rva );

	memcpy( eac_dll_fn, &entry_buffer[ 0 ], sizeof( entry_buffer ) );

	// EasyAntiCheat.dll returns 0 to prevent reverse engineers from using LoadLibraryA to unpack the module....
	const auto result = eac_dll_fn( image_base, reason, reserved );

	{
		dbg_print( "[EACMapper] DllMain returned: 0x%x", result );
		dbg_print( "[EACMapper] Hello World from RustClient.exe!" );
	}

	return result;
}