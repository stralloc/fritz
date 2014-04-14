#ifndef SELFTESTS_H
#define SELFTESTS_H

#include "stralloc.h"

int test_crypto_stream_xsalsa20_xor();
int test_crypto_box_static();
int test_crypto_box_beforenm_and_afternm();
int test_crypto_hash_sha256();
int test_crypto_hashblocks_sha256();

#endif