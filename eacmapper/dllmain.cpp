#include "stdfax.hpp"

void search_thread( void )
{
	while (true)
	{
		MEMORY_BASIC_INFORMATION mem_info{};

		for ( std::uint32_t base = 0; VirtualQuery(reinterpret_cast< void* >( base ), &mem_info, sizeof( MEMORY_BASIC_INFORMATION ) ); base += mem_info.RegionSize)
		{
			// x86 package is manual mapped, therefore we must pattern scan this address space for it's contents.
			// This doesn't necessarily take long, as we are running in a 32-bit address space where most memory will by skipped by VirtualQuery anyways.

			if ( mem_info.Protect == PAGE_EXECUTE_READWRITE && mem_info.State & MEM_COMMIT )
			{
				const auto result = 
					utils::find_pattern(reinterpret_cast< std::uint8_t* >( mem_info.BaseAddress ), mem_info.RegionSize, 
						reinterpret_cast<std::uint8_t*>( const_cast<char*>( "\x55\x8B\xEC\x81\xEC\xAA\xAA\xAA\xAA\x89\x4D\x94\x83\x65\xA0\x00" ) ), 16, 0xAA);

				if ( !result )
				{
					Sleep( 5 );
					continue;
				}

				hooks::image_fn.handler_func = &hooks::map_image;
				hooks::image_fn.hook_addr = result;
				hooks::image_fn.original = *reinterpret_cast< std::uint8_t* >( result );

				*reinterpret_cast< std::uint8_t* >( result ) = 0xCC;
				return ExitThread( 0xEAC );
			}
		}
	}

	return ExitThread( 0xDEAD );
}

long __stdcall veh_handler( _EXCEPTION_POINTERS* ctx )
{
	if ( ctx->ExceptionRecord->ExceptionAddress == hooks::image_fn.hook_addr && 
		ctx->ExceptionRecord->ExceptionCode == STATUS_BREAKPOINT )
	{
		return hooks::image_fn.handler_func( ctx->ContextRecord );
	}

	return EXCEPTION_CONTINUE_SEARCH;
}

bool dll_main( void ) 
{
	const auto init = []() -> bool
	{
		AddVectoredExceptionHandler(0, &veh_handler);

		const auto handle = CreateThread(nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(&search_thread), nullptr, 0, nullptr);
		if ( !handle || handle == INVALID_HANDLE_VALUE )
			return false;

		CloseHandle( handle );
		return true;
	};

	return init( );
}