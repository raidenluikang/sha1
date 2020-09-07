
#include <cstdio>
#include <cstdlib>
#include <string_view>
#include <array>
#include <cstdint>

static constexpr std::array<char,42> sha1(const ::std::string_view data) noexcept
{
    std::array<char,42> res = {};
    std::uint8_t u[64] = {};
    std::uint32_t w[16] = {};
    std::uint32_t h0 = 0, h1 = 0, h2 = 0, h3 = 0, h4 = 0;
    std::uint32_t a = 0, b = 0, c = 0, d = 0, e = 0;
    int i = 0;
    
    h0 = 0x67452301;
    h1 = 0xEFCDAB89;
    h2 = 0x98BADCFE;
    h3 = 0x10325476;
    h4 = 0xC3D2E1F0;

    auto fx = [](std::uint32_t b, std::uint32_t c, std::uint32_t d)
    {
        return (b & c) | ( (~b) & d);
    };
    auto fy = [](std::uint32_t b, std::uint32_t c, std::uint32_t d)
    {
        return (b ^ c ^ d );
    };
    auto fz = [](std::uint32_t b, std::uint32_t c, std::uint32_t d)
    {
        return (b & c) | (b & d) | (c & d);
    };
    
    auto rotate = [](std::uint32_t x, int n)
    {
        return (x << n)  | (x >> (32 - n));
    };

    auto process = [&]
    {
        for (int i= 0; i < 16; ++i)
        {
            w[i] = u[i*4];
            w[i] = (w[i] << 8) | u[i*4+1];
            w[i] = (w[i] << 8) | u[i*4+2];
            w[i] = (w[i] << 8) | u[i*4+3];
        }
        a = h0, b = h1, c = h2, d = h3, e = h4;
        for (int t = 0; t < 80; ++t){
            int s = t & 15;
            if (t >= 16){
                   w[s] = w[(s+13)&15] ^ w[(s+8)&15] ^ w[(s+2)&15] ^ w[s];
                   w[s] = rotate(w[s], 1);
            }
            int tmp = 0;
            if (t < 20){
                  tmp = rotate(a, 5) + fx(b,c,d) + e + w[s] + 0x5A827999;   
            } else if (t < 40){
                  tmp = rotate(a, 5) + fy(b,c,d) + e + w[s] + 0x6ED9EBA1;   

            } else if ( t < 60){
                  tmp = rotate(a, 5) + fz(b,c,d) + e + w[s] + 0x8F1BBCDC;   

            } else {
                  tmp = rotate(a, 5) + fy(b,c,d) + e + w[s] + 0xCA62C1D6;  

            }
            e = d; d = c; c = rotate(b, 30); b = a; a = tmp;
        }

        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
    };
    
    //add data
    for (unsigned char c : data)
    {
        u[i++] = c;
        if (i == 64){
            process();
            i = 0;
        }
    }

    //finish:
    u[i++] = 0x80;
    if (i > 56)
    {
        while (i<64)u[i++] = 0x00;
        process();
        i = 0;
    }

    while (i < 56)
        u[i++] = 0x00;

    std::uint64_t total_bits = data.size() * 8LL;
    u[56] = total_bits >> 56;
    u[57] = total_bits >> 48;
    u[58] = total_bits >> 40;
    u[59] = total_bits >> 32;
    u[60] = total_bits >> 24;
    u[61] = total_bits >> 16;
    u[62] = total_bits >> 8;
    u[63] = total_bits >> 0;

    process();

    i = 0;
    auto add= [&](int h){
        u[i++] = h >> 24;
        u[i++] = h >>16;
        u[i++] = h >> 8;
        u[i++] = h >> 0;
    };
    add(h0);
    add(h1);
    add(h2);
    add(h3);
    add(h4);

    for (int i = 0; i < 20; ++i)
    {
        res[ i * 2 + 0 ] = "0123456789ABCDEF" [ u[ i ] >> 4 ] ;
        res[ i * 2 + 1 ] = "0123456789ABCDEF" [ u[ i ] & 15 ] ;
    }
    return res;
}

int main()
{
    using namespace std::literals;
    constexpr auto digest = sha1("The quick brown fox jumps over the lazy dog"sv);
    printf("%s\n", digest.data());
    return 0;
}
