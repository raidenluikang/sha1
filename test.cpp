#include "sha1_contexpr.hpp"

#include <cstdio>
#include <chrono>
struct AutoCpuTimer
{
   std::chrono::high_resolution_clock::time_point start, finish;
   AutoCpuTimer(): start(std::chrono::high_resolution_clock::now()), finish(){}
   ~AutoCpuTimer(){
      finish = std::chrono::high_resolution_clock::now();
      double elapsed = std::chrono::duration<double>(finish - start).count();
      printf("elapsed: %.7f seconds.\n", elapsed);
   }
};

int main(int argc, char* argv[])
{
   if (argc != 2){
      printf("usage: %s <filename or full file-path>\n", argv[0]);
      return -2;
   }
   AutoCpuTimer cpuTimer;
   FILE* file = fopen(argv[1], "rb");
   if (!file){
      printf("ERROR: %s not found\n", argv[1]);
      return -3;
   }

   sha1::context ctx;
   constexpr std::size_t PAGE_SIZE = 8192 * 64;
   std::uint8_t * data = new std::uint8_t[PAGE_SIZE];
   while (true){
      std::size_t size = fread(data, 1, PAGE_SIZE, file);
      ctx.update(data, size);
      if (size < PAGE_SIZE)
         break;
   }
   delete [] data;
   fclose(file);

   ctx.finish();

   auto h = sha1::to_hex(ctx);
   printf("digest of `%s` file: %s\n", argv[1], h.hex);

   return 0;
}