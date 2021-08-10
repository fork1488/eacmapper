#pragma once

#include <Windows.h>
#include <intrin.h>

#include "minicrt.hpp"

namespace std
{
    using uint64_t = unsigned long long;
    using uint32_t = unsigned long;
    using uint16_t = unsigned short;
    using uint8_t = unsigned char;
}

using veh_func = long(*)( PCONTEXT );

struct veh_entry
{
    void* hook_addr;
    veh_func handler_func;
    std::uint8_t original;
};

static_assert( sizeof( void* ) == 4U, "this project is intended to be compiled in x86." );

// IMAGE_NT_HEADERS defaults to IMAGE_NT_HEADERS32 on x86 so we must adjust this.
#define IMAGE_FIRST_SECTION64( nt_header ) ((PIMAGE_SECTION_HEADER)         \
    ((std::uint32_t)(nt_header) +                                           \
     FIELD_OFFSET( IMAGE_NT_HEADERS64, OptionalHeader ) +                   \
     ((nt_header))->FileHeader.SizeOfOptionalHeader                         \
    ))

#include "dbg.hpp"
#include "utils.hpp"
#include "image.hpp"
#include "hooks.hpp"