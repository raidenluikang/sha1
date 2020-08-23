//https://tools.ietf.org/html/rfc3174
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <climits> 


#include <cstdio>

namespace sha1
{

struct output
{
	uint8_t bytes[20];
	char hex[42];
};

struct context
{
	context();
	
	int update(const uint8_t* data, size_t size);
	
	output result();
		
private:
	template <int n>
	static std::uint32_t shift_rotate(std::uint32_t x)
	{
		return (x << n) | (x >> (32-n));
	}
	void process();
	void finish();
private:
   std::uint8_t msg[64];
   int msg_index;
   std::uint32_t w[ 80 ];
   std::uint32_t lo_bits, hi_bits;
   
   std::uint32_t h1, h2, h3, h4, h5;
   
};	

context::context()
   : msg{}
   , msg_index{0}
   , w{}
   , lo_bits{0}
   , hi_bits{0}
   , h1{0x67452301}
   , h2{0xEFCDAB89}
   , h3{0x98BADCFE}
   , h4{0x10325476}
   , h5{0xC3D2E1F0}
{
}

output context::result()
{
	output o = {};
	finish();

	std::uint32_t h_array[] = {h1, h2, h3, h4, h5};
	int shifts[ 4 ] = {24, 16, 8, 0};

	for (int i = 0; i < 20; ++i)
	{
		std::uint8_t byte = (h_array[ i / 4 ] >> shifts[i%4]) & 0xff ;
		o.bytes[ i ] = byte;
		o.hex[i*2+0] = "0123456789abcdef" [byte >> 4];
		o.hex[i*2+1] = "0123456789abcdef" [byte & 15];
	}
	
	return o;
}

void context::process()
{
	std::uint32_t a = h1, b = h2, c = h3, d = h4, e = h5;
	std::uint32_t temp;
	
	for (int i = 0; i < 16; ++i)
	{
		w[i]  = static_cast<std::uint32_t>(msg[i*4+0]) << 24;
		w[i] |= static_cast<std::uint32_t>(msg[i*4+1]) << 16;
		w[i] |= static_cast<std::uint32_t>(msg[i*4+2]) << 8;
		w[i] |= static_cast<std::uint32_t>(msg[i*4+3]) << 0;
		 
	}
	for (int i = 16; i < 80; ++i){
		w[i] = shift_rotate<1>(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]);
	}
	std::uint32_t keys [] = {0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6};
	
	for (int t = 0; t < 20; ++t){
		 temp = shift_rotate<5>( a ) + ( (b&c) | ( (~b) & d) ) + e + w[ t ] + keys[ 0 ];
		  
		 e = d; 
		 d = c; 
		 c = shift_rotate<30>( b ); 
		 b = a; 
		 a = temp;
		
	}
	
	for (int t = 20; t < 40; ++t){
		 temp = shift_rotate<5>( a ) + ( b^c^d ) + e + w[ t ] + keys[ 1 ];
		  
		 e = d; 
		 d = c; 
		 c = shift_rotate<30>( b ); 
		 b = a; 
		 a = temp;
		
	}
	
	for (int t = 40; t < 60; ++t){
		 temp = shift_rotate<5>( a ) + ( (b & c) | (b & d) | (c & d) ) + e + w[ t ] + keys[ 2 ];
		  
		 e = d; 
		 d = c; 
		 c = shift_rotate<30>( b ); 
		 b = a; 
		 a = temp;
		
	}
	for (int t = 60; t < 80; ++t){
		 temp = shift_rotate<5>( a ) + ( b^c^d ) + e + w[ t ] + keys[ 3 ];
		  
		 e = d; 
		 d = c; 
		 c = shift_rotate<30>( b ); 
		 b = a; 
		 a = temp;
		
	}
		
	
	h1 += a;
	h2 += b;
	h3 += c;
	h4 += d;
	h5 += e;
}

int context::update(const uint8_t* data, size_t size)
{
	for (size_t i = 0; i < size; ++i)
	{
		lo_bits += 8;
		if (lo_bits == 0){
			hi_bits += 8;
		}
		msg[msg_index++] = data[i];
		if (msg_index == 64){
			process();
			msg_index = 0;
		}
	}
	return 0;
}
void context::finish()
{
	msg[msg_index++] = 0x80;

	if (msg_index > 56)
	{
		while (msg_index < 64)
			msg[msg_index++] = 0x00;
	
		process();
	
		msg_index = 0;
	}

	while (msg_index < 56)
		msg[msg_index++] = 0;
	
	msg[56] = hi_bits >> 24;
	msg[57] = hi_bits >> 16;
	msg[58] = hi_bits >> 8;
	msg[59] = hi_bits >> 0;
	
	msg[60] = lo_bits >> 24;
	msg[61] = lo_bits >> 16;
	msg[62] = lo_bits >> 8;
	msg[63] = lo_bits >> 0;
		
	process();

}

template <typename Byte>
output  result(const Byte* message, size_t size)
{
	static_assert(sizeof(Byte) == 1, "sizeof(Byte) == 1");
	
	context ctx;
	
	ctx.update((const uint8_t*)message, size);
	
	return ctx.result();
}

	
} // namespace sha1

int main()
{
	const char* msg = "В чащах юга жил бы цитрус? Да, но фальшивый экземпляр!";//"The quick brown fox jumps over the lazy dog";
	
	auto o = sha1::result(msg, strlen(msg));
	
	printf("%s\n", o.hex);
}
