#pragma once

#include <cstdint>
#include <cstddef>
#include <cstring>

#include <cstdio> // debug purpose

namespace sha1
{

struct values
{
    std::uint32_t a, b, c, d, e;
};

template <std::size_t n>
constexpr std::uint32_t rol(const std::uint32_t value)
{
    return (value << n) | (value >> (32 - n));
}


struct str_out
{
   char hex[ 42 ];
};

constexpr bool operator == (const str_out& lhs, const str_out& rhs) noexcept
{
    return memcmp(lhs.hex, rhs.hex, 40) == 0;
}   

struct byte_out
{
    std::uint8_t bytes[20];
};

constexpr bool operator == (const byte_out& lhs, const byte_out& rhs) noexcept
{
    return memcmp(lhs.bytes, rhs.bytes, 20) == 0;
}


struct context
{
     std::uint32_t words[ 16 ];  
     std::uint8_t bytes[ 64 ];
     std::uint64_t total_bits;
     std::uint32_t index_byte;
     values parameters;
     
    constexpr context() noexcept
        : words{}
        , bytes{}
        , total_bits{0}
        , index_byte{0}
        , parameters { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 }
    {}
    
    constexpr void update(const std::uint8_t* data, std::size_t size ) noexcept;
    constexpr void finish() noexcept;
    
    constexpr std::size_t to_hex(char* out) const noexcept;
    constexpr std::size_t to_bytes(std::uint8_t* out) const noexcept;
 private:
     constexpr void process_bytes(const std::uint8_t* bytes) noexcept;   
};

// some compilers(G++, Clang++, ) generated a single bswap instruction.
constexpr std::uint32_t swap_uint32( std::uint32_t val )
{
    val = ((val << 8) & 0xFF00FF00 ) | ((val >> 8) & 0xFF00FF ); 
    return (val << 16) | (val >> 16);
}

constexpr void context::process_bytes(const std::uint8_t* bytes) noexcept
{
 
    std::uint32_t a = parameters.a;
    std::uint32_t b = parameters.b;
    std::uint32_t c = parameters.c;
    std::uint32_t d = parameters.d;
    std::uint32_t e = parameters.e;

    memcpy(words, bytes, 64);
    for (std::size_t i = 0; i < 16; ++i)
    {
        words[i] = swap_uint32(words[i]);
    }

#define fx(b,c,d)  ((b & c) | ((~b) & d))
#define fy(b,c,d)  (b ^ c ^ d)
#define fz(b,c,d)  ((b & c) |(b & d) | (c & d))

#define R_UPD(s) words[s] = rol<1>(words[(s + 13 ) & 15 ] ^ words[ (s + 8) & 15] ^ words[( s + 2) & 15] ^ words[s]);
#define R0(a,b,c,d,e, s, func, key) e = rol<5>(a) + func(b,c,d) + e + words[s] + key; b = rol<30>(b);
#define R1(a,b,c,d,e, s, func, key)  R_UPD(s) R0(a,b,c,d,e,s,func,key)
    
    R0( a, b, c, d, e, 0, fx, 0x5A827999 )
    R0( e, a, b, c, d, 1, fx, 0x5A827999 )
    R0( d, e, a, b, c, 2, fx, 0x5A827999 )
    R0( c, d, e, a, b, 3, fx, 0x5A827999 )
    R0( b, c, d, e, a, 4, fx, 0x5A827999 )

    R0( a, b, c, d, e, 5, fx, 0x5A827999 )
    R0( e, a, b, c, d, 6, fx, 0x5A827999 )
    R0( d, e, a, b, c, 7, fx, 0x5A827999 )
    R0( c, d, e, a, b, 8, fx, 0x5A827999 )
    R0( b, c, d, e, a, 9, fx, 0x5A827999 )
    
    R0( a, b, c, d, e, 10, fx, 0x5A827999 )
    R0( e, a, b, c, d, 11, fx, 0x5A827999 )
    R0( d, e, a, b, c, 12, fx, 0x5A827999 )
    R0( c, d, e, a, b, 13, fx, 0x5A827999 )
    R0( b, c, d, e, a, 14, fx, 0x5A827999 )
    

    R0( a, b, c, d, e, 15, fx, 0x5A827999 )
    R1( e, a, b, c, d, 0, fx, 0x5A827999 )
    R1( d, e, a, b, c, 1, fx, 0x5A827999 )
    R1( c, d, e, a, b, 2, fx, 0x5A827999 )
    R1( b, c, d, e, a, 3, fx, 0x5A827999 )
    
    /// t >= 20 .. 39
    R1( a, b, c, d, e, 4, fy, 0x6ED9EBA1 )
    R1( e, a, b, c, d, 5, fy, 0x6ED9EBA1 )
    R1( d, e, a, b, c, 6, fy, 0x6ED9EBA1 )
    R1( c, d, e, a, b, 7, fy, 0x6ED9EBA1 )
    R1( b, c, d, e, a, 8, fy, 0x6ED9EBA1 )

    R1( a, b, c, d, e, 9, fy, 0x6ED9EBA1 )
    R1( e, a, b, c, d, 10, fy, 0x6ED9EBA1 )
    R1( d, e, a, b, c, 11, fy, 0x6ED9EBA1 )
    R1( c, d, e, a, b, 12, fy, 0x6ED9EBA1 )
    R1( b, c, d, e, a, 13, fy, 0x6ED9EBA1 )
    
    R1( a, b, c, d, e, 14, fy, 0x6ED9EBA1 )
    R1( e, a, b, c, d, 15, fy, 0x6ED9EBA1 )
    R1( d, e, a, b, c, 0, fy, 0x6ED9EBA1 )
    R1( c, d, e, a, b, 1, fy, 0x6ED9EBA1 )
    R1( b, c, d, e, a, 2, fy, 0x6ED9EBA1 )
    

    R1( a, b, c, d, e, 3, fy, 0x6ED9EBA1 )
    R1( e, a, b, c, d, 4, fy, 0x6ED9EBA1 )
    R1( d, e, a, b, c, 5, fy, 0x6ED9EBA1 )
    R1( c, d, e, a, b, 6, fy, 0x6ED9EBA1 )
    R1( b, c, d, e, a, 7, fy, 0x6ED9EBA1 )

    // t >= 40 .. 59
    R1( a, b, c, d, e, 8, fz, 0x8F1BBCDC )
    R1( e, a, b, c, d, 9, fz, 0x8F1BBCDC )
    R1( d, e, a, b, c, 10, fz, 0x8F1BBCDC )
    R1( c, d, e, a, b, 11, fz, 0x8F1BBCDC )
    R1( b, c, d, e, a, 12, fz, 0x8F1BBCDC )

    R1( a, b, c, d, e, 13, fz, 0x8F1BBCDC )
    R1( e, a, b, c, d, 14, fz, 0x8F1BBCDC )
    R1( d, e, a, b, c, 15, fz, 0x8F1BBCDC )
    R1( c, d, e, a, b, 0, fz, 0x8F1BBCDC )
    R1( b, c, d, e, a, 1, fz, 0x8F1BBCDC )
    
    R1( a, b, c, d, e, 2, fz, 0x8F1BBCDC )
    R1( e, a, b, c, d, 3, fz, 0x8F1BBCDC )
    R1( d, e, a, b, c, 4, fz, 0x8F1BBCDC )
    R1( c, d, e, a, b, 5, fz, 0x8F1BBCDC )
    R1( b, c, d, e, a, 6, fz, 0x8F1BBCDC )
    

    R1( a, b, c, d, e, 7, fz, 0x8F1BBCDC )
    R1( e, a, b, c, d, 8, fz, 0x8F1BBCDC )
    R1( d, e, a, b, c, 9, fz, 0x8F1BBCDC )
    R1( c, d, e, a, b, 10, fz, 0x8F1BBCDC )
    R1( b, c, d, e, a, 11, fz, 0x8F1BBCDC )

    // t >= 60 .. 79
    R1( a, b, c, d, e, 12, fy, 0xCA62C1D6 )
    R1( e, a, b, c, d, 13, fy, 0xCA62C1D6 )
    R1( d, e, a, b, c, 14, fy, 0xCA62C1D6 )
    R1( c, d, e, a, b, 15, fy, 0xCA62C1D6 )
    R1( b, c, d, e, a, 0, fy, 0xCA62C1D6 )

    R1( a, b, c, d, e, 1, fy, 0xCA62C1D6 )
    R1( e, a, b, c, d, 2, fy, 0xCA62C1D6 )
    R1( d, e, a, b, c, 3, fy, 0xCA62C1D6 )
    R1( c, d, e, a, b, 4, fy, 0xCA62C1D6 )
    R1( b, c, d, e, a, 5, fy, 0xCA62C1D6 )
    
    R1( a, b, c, d, e, 6, fy, 0xCA62C1D6 )
    R1( e, a, b, c, d, 7, fy, 0xCA62C1D6 )
    R1( d, e, a, b, c, 8, fy, 0xCA62C1D6 )
    R1( c, d, e, a, b, 9, fy, 0xCA62C1D6 )
    R1( b, c, d, e, a, 10, fy, 0xCA62C1D6 )
    

    R1( a, b, c, d, e, 11, fy, 0xCA62C1D6 )
    R1( e, a, b, c, d, 12, fy, 0xCA62C1D6 )
    R1( d, e, a, b, c, 13, fy, 0xCA62C1D6 )
    R1( c, d, e, a, b, 14, fy, 0xCA62C1D6 )
    R1( b, c, d, e, a, 15, fy, 0xCA62C1D6 )
     
 #undef fx
 #undef fy
 #undef fz
 #undef R0
 #undef R1

    parameters.a += a;
    parameters.b += b;
    parameters.c += c;
    parameters.d += d;
    parameters.e += e;
}


constexpr void context::update(const std::uint8_t* data, std::size_t size ) noexcept
{
    total_bits += static_cast<std::uint64_t>(size) * 8;
    
    if (size + index_byte >= 64 )
    {
        if (index_byte > 0){
            const std::size_t diff = 64 - index_byte;
            memcpy(bytes + index_byte, data, diff);
            data += diff;
            size -= diff;
            process_bytes(bytes);
        }

        const std::size_t number = (size / 64) * 64;
        
        for (std::size_t index = 0; index < number; index += 64)
            process_bytes(data + index );
        
        data += number;
        size -= number;

        index_byte = size;
        if (size > 0)
        {
            memcpy(bytes, data, size);
        }
    } else if (size > 0){
        memcpy(bytes + index_byte, data, size);
        index_byte += size;
    }

    
}
    
constexpr void context::finish() noexcept
{ 
        if (index_byte >= 56){
            bytes[index_byte++] = 0x80;
            while (index_byte < 64)
                bytes[index_byte++] = 0x00;
            process_bytes(bytes);

            memset(bytes, 0, sizeof(bytes));
            bytes[56] = total_bits >> 56;
            bytes[57] = total_bits >> 48;
            bytes[58] = total_bits >> 40;
            bytes[59] = total_bits >> 32;
            bytes[60] = total_bits >> 24;
            bytes[61] = total_bits >> 16;
            bytes[62] = total_bits >> 8;
            bytes[63] = total_bits >> 0;

            process_bytes(bytes);
        }  else {
            bytes[index_byte++] = 0x80;
            while (index_byte < 56 )
                bytes[index_byte++] = 0x00;

            bytes[56] = total_bits >> 56;
            bytes[57] = total_bits >> 48;
            bytes[58] = total_bits >> 40;
            bytes[59] = total_bits >> 32;
            bytes[60] = total_bits >> 24;
            bytes[61] = total_bits >> 16;
            bytes[62] = total_bits >> 8;
            bytes[63] = total_bits >> 0;

            process_bytes(bytes);

        }
}
 
    
constexpr std::size_t context::to_hex(char * out) const noexcept
{
    constexpr std::size_t sz = 20;
    
    std::uint8_t bx[sz] = {};
    
    to_bytes(bx);

    for (std::size_t ix = 0; ix != sz; ++ix)
    {
        unsigned x = bx[ix];
        out[ix * 2] = "0123456789abcdef"[x >> 4];
        out[ix * 2 + 1 ] = "0123456789abcdef"[x & 15];
    }
    
    out[ sz * 2 ] = '\0';
    
    return sz * 2;
}

constexpr std::size_t context::to_bytes(std::uint8_t* out) const noexcept
{
    constexpr std::size_t sz = 20;
    std::size_t i = 0;

    const auto add = [&](const std::uint32_t x)
    {
            out[i++] = x >> 24;
            out[i++] = x >> 16;
            out[i++] = x >> 8;
            out[i++] = x;
    };
    add(parameters.a);
    add(parameters.b);
    add(parameters.c);
    add(parameters.d);
    add(parameters.e);
    return sz;
}
    
constexpr str_out to_hex(context const& ctx) noexcept
{
    str_out out = {};
    ctx.to_hex(out.hex);
    return out;
}
    
constexpr byte_out to_bytes(context const& ctx) noexcept
{
    byte_out out = {};
    ctx.to_bytes(out.bytes);
    return out;
}
 
constexpr str_out digest_hex(const char* data, std::size_t len)
{
    context ctx;
    ctx.update((std::uint8_t*)data, len);
    ctx.finish();
    return to_hex(ctx);
}

} // sha1 namespace
