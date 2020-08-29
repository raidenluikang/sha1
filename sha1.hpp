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
        , parameters(default_values())
    {}
    
    constexpr void update(const std::uint8_t* data, std::size_t size ) noexcept;
    constexpr void finish() noexcept;
    
    constexpr std::size_t to_hex(char* out) const noexcept;
    constexpr std::size_t to_bytes(std::uint8_t* out) const noexcept;
 private:
     constexpr void process_bytes(const std::uint8_t* bytes) noexcept;   
};

constexpr void context::process_bytes(const std::uint8_t* bytes) noexcept
{
    std::uint32_t a = parameters.a;
    std::uint32_t b = parameters.b;
    std::uint32_t c = parameters.c;
    std::uint32_t d = parameters.d;
    std::uint32_t e = parameters.e;
    std::uint32_t tmp = 0;

    for (std::size_t i = 0; i < 16; ++i)
    {
        words[i] = static_cast<std::uint32_t>(bytes[i*4 + 0]) << 24 | 
                   static_cast<std::uint32_t>(bytes[i*4 + 1]) << 16 | 
                   static_cast<std::uint32_t>(bytes[i*4 + 2]) << 8  | 
                   static_cast<std::uint32_t>(bytes[i*4 + 3]);
    }

    using func_type = std::uint32_t(*)(std::uint32_t, std::uint32_t, std::uint32_t);

    constexpr values keys_tmp = key_values();
    
    constexpr std::uint32_t keys[4] = {keys_tmp.a, keys_tmp.b, keys_tmp.c, keys_tmp.d};

    constexpr func_type funcs[4] = 
    {
        +[](std::uint32_t b, std::uint32_t c, std::uint32_t d)
        {
            return (b & c) | (~b & d); 
        },
        
        +[](std::uint32_t b, std::uint32_t c, std::uint32_t d)
        {
            return b^ c ^ d;
        },
        
        +[](std::uint32_t b, std::uint32_t c, std::uint32_t d)
        {
            return (b & c) | (b & d) | (c & d);
        },
    
        +[](std::uint32_t b, std::uint32_t c, std::uint32_t d)
        {
            return b^ c ^ d;
        }
    };
    
    for (int t = 0; t < 80; ++t)
    {
        int s = t & 0x0f;
        if (t >= 16){
            words[s] = rol<1>(words[(s + 13 ) & 15 ] ^ words[ (s + 8) & 15] ^ words[( s + 2) & 15] ^ words[s]); 
        }

        tmp = rol<5>(a) + (funcs[t/20])(b,c,d) + e + words[s] + keys[t/20];


        e = d;
        d = c;
        c = rol<30>(b);
        b = a;
        a = tmp;
    }

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


// test

