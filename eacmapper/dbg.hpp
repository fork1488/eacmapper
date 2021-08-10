#pragma once
#include "stdfax.hpp"

namespace dbg
{
	void dbg_print( const char* msg, ... )
	{
		va_list args;
		va_start( args, msg );

		char buffer[512];
		memset( buffer, 0, sizeof( buffer ) );
		mini_vsprintf_s( buffer, sizeof( buffer ), msg, args );

		OutputDebugStringA( buffer );
		return va_end(args);
	}
}