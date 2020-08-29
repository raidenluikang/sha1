#include "sha1.hpp"


int main()
{
    static_assert(sha1::digest_hex("", 0) == sha1::str_out{"da39a3ee5e6b4b0d3255bfef95601890afd80709"});
}