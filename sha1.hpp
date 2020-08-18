#pragma once

#include <cstdint>
#include <cstddef>
#include <cstring>

namespace sha1
{

enum : std::size_t
{
    block_size   = 16 ,
    total_blocks = 80 ,
    output_bytes = 20 ,
    
    message_block = 64 , // 64 bytes = 512 bits
};
    
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

template <std::size_t n>
constexpr std::uint32_t rol(const std::uint32_t value)
{
    return (value << n) | (value >> (32 - n));
}

struct block_t
{
    std::uint32_t w[block_size];

    template <std::size_t i>
    constexpr std::uint32_t blk() const noexcept
    {
        return rol<1>(w[(i + 13) & 15] ^ w[(i + 8) & 15] ^ w[(i + 2) & 15] ^ w[i]);
    }

};

/*
 * (R0+R1), R2, R3, R4 are the different operations used in SHA1
 */

constexpr void F0(const std::uint32_t block[BLOCK_INTS], const uint32_t v, uint32_t& w, const uint32_t x, const uint32_t y, uint32_t& z, const size_t i)
{
    z += ((w & (x ^ y)) ^ y) + block[i] + 0x5a827999 + rol(v, 5);
    w = rol(w, 30);
}


inline static void R1(uint32_t block[BLOCK_INTS], const uint32_t v, uint32_t& w, const uint32_t x, const uint32_t y, uint32_t& z, const size_t i)
{
    block[i] = blk(block, i);
    z += ((w & (x ^ y)) ^ y) + block[i] + 0x5a827999 + rol(v, 5);
    w = rol(w, 30);
}


inline static void R2(uint32_t block[BLOCK_INTS], const uint32_t v, uint32_t& w, const uint32_t x, const uint32_t y, uint32_t& z, const size_t i)
{
    block[i] = blk(block, i);
    z += (w ^ x ^ y) + block[i] + 0x6ed9eba1 + rol(v, 5);
    w = rol(w, 30);
}


inline static void R3(uint32_t block[BLOCK_INTS], const uint32_t v, uint32_t& w, const uint32_t x, const uint32_t y, uint32_t& z, const size_t i)
{
    block[i] = blk(block, i);
    z += (((w | x) & y) | (w & x)) + block[i] + 0x8f1bbcdc + rol(v, 5);
    w = rol(w, 30);
}


inline static void R4(uint32_t block[BLOCK_INTS], const uint32_t v, uint32_t& w, const uint32_t x, const uint32_t y, uint32_t& z, const size_t i)
{
    block[i] = blk(block, i);
    z += (w ^ x ^ y) + block[i] + 0xca62c1d6 + rol(v, 5);
    w = rol(w, 30);
}



struct str_out
{
   char hex[ 2 + output_bytes * 2 ];
};
    
struct byte_out
{
    std::uint8_t bytes[output_bytes];
};
    
struct context
{
     std::uint32_t words[ 16 ];  
     std::size_t size;
     values parameters;
     
    constexpr context() noexcept
        : bytes{}, size(0), parameters(default_values())
    {}
    
    constexpr void add(const std::uint8_t* data, std::size_t size ) noexcept;
    constexpr void finish(const std::uint8_t* data, std::size_t size) noexcept;
    
    constexpr std::size_t hex(char* out) const noexcept;
    constexpr std::size_t bytes(std::uint8_t* out) const noexcept;
 private:
     constexpr void process_bytes() noexcept;   
};
    
constexpr void context::add(const std::uint8_t* data, std::size_t size ) noexcept
{
    while (size > 0)
    {
       size --;
       bytes[this->size++] = *data++;
       if (this->size == message_block ){
           process_bytes();
           this->size = 0;
       }
    }
}
    
constexpr void context::finish(const std::uint8_t* data, std::size_t size) noexcept
{
    add(data,size);
    
}
 
    
constexpr std::size_t context::hex(char * out) const noexcept
{
    constexpr std::size_t sz = output_size;
    for (std::size_t ix = 0; ix != sz; ++ix){
        unsigned x = bytes[ix];
        out[ix * 2] = "0123456789ABCDEF"[x >> 4];
        out[ix * 2 + 1 ] = "0123456789ABCDEF"[x & 15];
    }
    out[ sz * 2 ] = '\0';
    
    return sz * 2;
}
constexpr std::size_t context::bytes(std::uint8_t* out) const noexcept
{
    constexpr std::size_t sz = output_size;
    for (std::size_t ix = 0; ix != sz; ++ix){
         *out++ = words[ix];
    }
    return sz;
}
    
constexpr str_out hex(context const& ctx) noexcept
{
    str_out out = {};
    ctx.hex(out.hex);
    return out;
}
    
constexpr byte_out bytes(context const& ctx) noexcept
{
    byte_out out = {};
    ctx.bytes(out.bytes);
    return out;
}


} // sha1 namespace
