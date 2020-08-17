#pragma once

#include <cstdint>
#include <cstddef>

namespace sha1
{

constexpr std::size_t  output_size() noexcept { return 20; }

struct values
{
    std::uint32_t a, b, c, d, e;
};

constexpr values default_values() noexcept
{
    return { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 };
}

constexpr values  key_values() noexcept
{
    return {0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6, 0};
}

struct context
{
     std::uint8_t bytes[output_size()];  
     values parameters;
     
};



struct str_out
{
   char hex[ 42 ];
};

constexpr str_out hex(context const& ctx) noexcept
{
    str_out out = {};
    constexpr std::size_t sz = output_size();
    for (std::size_t ix = 0; ix != sz; ++ix){
        unsigned x = bytes[ix];
        out.hex[ix * 2] = "0123456789ABCDEF"[x >> 4];
        out.hex[ix * 2 + 1 ] = "0123456789ABCDEF"[x & 15];
    }
    return out;
}



} // sha1 namespace
