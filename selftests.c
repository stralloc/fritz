#include <windows.h>

#include "selftests.h"

#ifndef WITH_LIBSODIUM
	#include "crypto_stream_xsalsa20.h"
	#include "crypto_hash_sha256.h"
	#include "crypto_hashblocks_sha256.h"
	#include "crypto_box.h"
#else
	#include "sodium.h"
#endif

void secure_randombytes(unsigned char *,DWORD);

int test_crypto_stream_xsalsa20_xor() {

	int i;

	unsigned char firstkey[32] = {
	 0x1b,0x27,0x55,0x64,0x73,0xe9,0x85,0xd4
	,0x62,0xcd,0x51,0x19,0x7a,0x9a,0x46,0xc7
	,0x60,0x09,0x54,0x9e,0xac,0x64,0x74,0xf2
	,0x06,0xc4,0xee,0x08,0x44,0xf6,0x83,0x89
	} ;

	unsigned char nonce[24] = {
	 0x69,0x69,0x6e,0xe9,0x55,0xb6,0x2b,0x73
	,0xcd,0x62,0xbd,0xa8,0x75,0xfc,0x73,0xd6
	,0x82,0x19,0xe0,0x03,0x6b,0x7a,0x0b,0x37
	} ;

	unsigned char m[163] = {
		0,   0,   0,   0,   0,   0,   0,   0
	,   0,   0,   0,   0,   0,   0,   0,   0
	,   0,   0,   0,   0,   0,   0,   0,   0
	,   0,   0,   0,   0,   0,   0,   0,   0
	,0xbe,0x07,0x5f,0xc5,0x3c,0x81,0xf2,0xd5
	,0xcf,0x14,0x13,0x16,0xeb,0xeb,0x0c,0x7b
	,0x52,0x28,0xc5,0x2a,0x4c,0x62,0xcb,0xd4
	,0x4b,0x66,0x84,0x9b,0x64,0x24,0x4f,0xfc
	,0xe5,0xec,0xba,0xaf,0x33,0xbd,0x75,0x1a
	,0x1a,0xc7,0x28,0xd4,0x5e,0x6c,0x61,0x29
	,0x6c,0xdc,0x3c,0x01,0x23,0x35,0x61,0xf4
	,0x1d,0xb6,0x6c,0xce,0x31,0x4a,0xdb,0x31
	,0x0e,0x3b,0xe8,0x25,0x0c,0x46,0xf0,0x6d
	,0xce,0xea,0x3a,0x7f,0xa1,0x34,0x80,0x57
	,0xe2,0xf6,0x55,0x6a,0xd6,0xb1,0x31,0x8a
	,0x02,0x4a,0x83,0x8f,0x21,0xaf,0x1f,0xde
	,0x04,0x89,0x77,0xeb,0x48,0xf5,0x9f,0xfd
	,0x49,0x24,0xca,0x1c,0x60,0x90,0x2e,0x52
	,0xf0,0xa0,0x89,0xbc,0x76,0x89,0x70,0x40
	,0xe0,0x82,0xf9,0x37,0x76,0x38,0x48,0x64
	,0x5e,0x07,0x05
	} ;

	unsigned char c[163];

	unsigned char out[133] = {
	0x8e,0x99,0x3b,0x9f,0x48,0x68,0x12,0x73
	,0xc2,0x96,0x50,0xba,0x32,0xfc,0x76,0xce
	,0x48,0x33,0x2e,0xa7,0x16,0x4d,0x96,0xa4
	,0x47,0x6f,0xb8,0xc5,0x31,0xa1,0x18,0x6a
	,0xc0,0xdf,0xc1,0x7c,0x98,0xdc,0xe8,0x7b
	,0x4d,0xa7,0xf0,0x11,0xec,0x48,0xc9,0x72
	,0x71,0xd2,0xc2,0x0f,0x9b,0x92,0x8f,0xe2
	,0x27,0x0d,0x6f,0xb8,0x63,0xd5,0x17,0x38
	,0xb4,0x8e,0xee,0xe3,0x14,0xa7,0xcc,0x8a
	,0xb9,0x32,0x16,0x45,0x48,0xe5,0x26,0xae
	,0x90,0x22,0x43,0x68,0x51,0x7a,0xcf,0xea
	,0xbd,0x6b,0xb3,0x73,0x2b,0xc0,0xe9,0xda
	,0x99,0x83,0x2b,0x61,0xca,0x01,0xb6,0xde
	,0x56,0x24,0x4a,0x9e,0x88,0xd5,0xf9,0xb3
	,0x79,0x73,0xf6,0x22,0xa4,0x3d,0x14,0xa6
	,0x59,0x9b,0x1f,0x65,0x4c,0xb4,0x5a,0x74
	,0xe3,0x55,0xa5};

	crypto_stream_xsalsa20_xor(c,m,163,nonce,firstkey);
	
	for (i = 32;i < 163;++i) {
		if((unsigned int)c[i]!=(unsigned int)out[i-32]) return 0;
	}
	return 1;
}

int test_crypto_box_static() {

	unsigned char m[163] = {
		0,   0,   0,   0,   0,   0,   0,   0
	,   0,   0,   0,   0,   0,   0,   0,   0
	,   0,   0,   0,   0,   0,   0,   0,   0
	,   0,   0,   0,   0,   0,   0,   0,   0
	,0xbe,0x07,0x5f,0xc5,0x3c,0x81,0xf2,0xd5
	,0xcf,0x14,0x13,0x16,0xeb,0xeb,0x0c,0x7b
	,0x52,0x28,0xc5,0x2a,0x4c,0x62,0xcb,0xd4
	,0x4b,0x66,0x84,0x9b,0x64,0x24,0x4f,0xfc
	,0xe5,0xec,0xba,0xaf,0x33,0xbd,0x75,0x1a
	,0x1a,0xc7,0x28,0xd4,0x5e,0x6c,0x61,0x29
	,0x6c,0xdc,0x3c,0x01,0x23,0x35,0x61,0xf4
	,0x1d,0xb6,0x6c,0xce,0x31,0x4a,0xdb,0x31
	,0x0e,0x3b,0xe8,0x25,0x0c,0x46,0xf0,0x6d
	,0xce,0xea,0x3a,0x7f,0xa1,0x34,0x80,0x57
	,0xe2,0xf6,0x55,0x6a,0xd6,0xb1,0x31,0x8a
	,0x02,0x4a,0x83,0x8f,0x21,0xaf,0x1f,0xde
	,0x04,0x89,0x77,0xeb,0x48,0xf5,0x9f,0xfd
	,0x49,0x24,0xca,0x1c,0x60,0x90,0x2e,0x52
	,0xf0,0xa0,0x89,0xbc,0x76,0x89,0x70,0x40
	,0xe0,0x82,0xf9,0x37,0x76,0x38,0x48,0x64
	,0x5e,0x07,0x05
	} ;

	unsigned char alicepk[crypto_box_PUBLICKEYBYTES] = {
	0xf5,0x88,0x6a,0x3b,0x62,0xf8,0xf1,0xa2
	,0x94,0x49,0x51,0x8c,0x71,0x8f,0xe0,0xb0
	,0xb9,0x74,0x08,0x71,0x31,0x62,0x7e,0x46
	,0x9e,0xf9,0x23,0xb4,0xfc,0x9c,0xe0,0x06
	};

	unsigned char bobsk[crypto_box_SECRETKEYBYTES] = {
	0xd5,0x22,0x4d,0x85,0x6c,0x1d,0x42,0xc1
	,0xe2,0xb0,0xb7,0xa4,0xd1,0x06,0x78,0x33
	,0xd0,0xa9,0x46,0x82,0x40,0x1e,0xb4,0x9c
	,0xec,0x6f,0x22,0xe3,0x9e,0x19,0x4e,0x32
	};

	unsigned char n[crypto_box_NONCEBYTES] = {
	0x7b,0xa5,0x8c,0xd5,0x91,0x85,0xa6,0xff
	,0x30,0x7c,0x8d,0x67,0xf8,0x7a,0xf0,0x93
	,0xec,0x95,0x5f,0x9b,0x80,0x3a,0xcc,0x84
	};

	unsigned char c[163] = {
	0x0e,0xde,0x76,0x98,0x99,0x8c,0xfb,0xff
	,0xe3,0x39,0xfd,0x83,0xd1,0xcf,0xeb,0xca
	,0x40,0x9c,0x43,0xe0,0x16,0x8c,0x24,0x4d
	,0x48,0x62,0xab,0xf7,0xb7,0xa8,0x91,0x49
	,0x0e,0xc5,0xb8,0x32,0x59,0x7c,0x31,0x95
	,0xa0,0x3c,0x36,0x19,0x09,0x88,0x1b,0xf0
	,0xa0,0x51,0x68,0x7b,0x84,0xa1,0x76,0x8b
	,0x3e,0x90,0x0d,0x23,0x08,0x2c,0x15,0xf3
	,0xb4,0x14,0x04,0xfb,0x38,0x0b,0xe8,0x79
	,0xd3,0x9b,0x76,0xf2,0xd4,0xfa,0x4f,0xa8
	,0x0a,0x22,0x23,0x3f,0x4d,0x72,0xd0,0xd3
	,0xa4,0x1b,0x2a,0x31,0x03,0x1e,0x64,0x13
	,0xec,0xe1,0xac,0xff,0x8e,0xa3,0xb3,0xd3
	,0xf4,0x2e,0x95,0x1d,0x92,0x9b,0xd8,0x3e
	,0xc7,0x3d,0x16,0x9a,0xfa,0x09,0x38,0xdd
	,0x13,0xc7,0x26,0xa7,0xaf,0x4b,0x50,0x18
	,0x7f,0x67,0x7d};	
	
	unsigned char c2[163];
	int i;	

	crypto_box(c2,m,163,n,alicepk,bobsk);

	for(i=0;i<163-crypto_box_ZEROBYTES;i++) {
		if((unsigned int) c[i]!= (unsigned int)c2[i+crypto_box_ZEROBYTES]) return 0;
	}
	return 1;
}

int test_crypto_box_beforenm_and_afternm() {

	unsigned char alicesk[crypto_box_SECRETKEYBYTES];
	unsigned char alicepk[crypto_box_PUBLICKEYBYTES];
	unsigned char bobsk[crypto_box_SECRETKEYBYTES];
	unsigned char bobpk[crypto_box_PUBLICKEYBYTES];
	unsigned char k[crypto_box_BEFORENMBYTES];
	unsigned char n[crypto_box_NONCEBYTES];
	unsigned char m[5000];
	unsigned char c[5000];
	unsigned char m2[5000];

	int mlen = 4048;
	int i;

	crypto_box_keypair(alicepk,alicesk);
	crypto_box_keypair(bobpk,bobsk);
	
	secure_randombytes(n,crypto_box_NONCEBYTES);
	secure_randombytes(m + crypto_box_ZEROBYTES,mlen);
	
	crypto_box_beforenm(k,bobpk,alicesk);
	crypto_box_afternm(c,m,mlen + crypto_box_ZEROBYTES,n,k);

	crypto_box_beforenm(k,alicepk,bobsk);
	if (crypto_box_open_afternm(m2,c,mlen + crypto_box_BOXZEROBYTES,n,k) == 0) {
		for (i = 0;i < mlen + crypto_box_ZEROBYTES;++i)
			if (m2[i] != m[i]) {
				return 0;
			}
	}

	return 1;
}

int test_crypto_hash_sha256() {
 
	unsigned char x[8] = "testing\n";
	unsigned char h[crypto_hash_sha256_BYTES];
	unsigned char out[crypto_hash_sha256_BYTES] = {
	0x12,0xa6,0x1f,0x4e,0x17,0x3f,0xb3,0xa1
	,0x1c,0x05,0xd6,0x47,0x1f,0x74,0x72,0x8f
	,0x76,0x23,0x1b,0x4a,0x5f,0xcd,0x96,0x67
	,0xce,0xf3,0xaf,0x87,0xa3,0xae,0x4d,0xc2};
	int i;
	
	crypto_hash_sha256(h,x,sizeof x);

	for (i = 0;i < crypto_hash_sha256_BYTES;++i)
		if((unsigned int) h[i] != (unsigned int)out[i]) return 0;
	return 1;
}

int test_crypto_hashblocks_sha256() {
 
	unsigned char x[8] = "testing\n";
	unsigned char h[crypto_hash_sha256_BYTES];
	unsigned char out[crypto_hash_sha256_BYTES] = {
	0x12,0xa6,0x1f,0x4e,0x17,0x3f,0xb3,0xa1
	,0x1c,0x05,0xd6,0x47,0x1f,0x74,0x72,0x8f
	,0x76,0x23,0x1b,0x4a,0x5f,0xcd,0x96,0x67
	,0xce,0xf3,0xaf,0x87,0xa3,0xae,0x4d,0xc2};
	int i;
	
	crypto_hashblocks_sha256(h,x,sizeof x);

	for (i = 0;i < crypto_hash_sha256_BYTES;++i)
		if((unsigned int) h[i] != (unsigned int)out[i]) return 0;
	return 1;
}