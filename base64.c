#include <stdio.h>
#include <string.h>

#include "base64.h"

static const char base64[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=";

int isBase64(const char *str, unsigned int param) {
	size_t i,j;
	size_t len = strlen(str);
	size_t len_digits = strlen(base64);
	int is_base64 = 0;

	for(i=0;i<len;i++) {
		is_base64 = 0;

		if(param==BASE64_IGNORE_WHITESPACE) {
			switch(str[i]) {
				case '\r':
				case '\n':
				case ' ':
				case '\t': continue;
				default: break;
			}
		}

		for(j=0;j<len_digits;j++) {
			if(str[i]==base64[j]||str[i]=='=') is_base64=1;
		}
		
		if(is_base64==0) {
			return 0;
		}
	}
	return 1;
}

size_t base64_len(size_t len) {
	if(((len+2)/3)*4<len) return 0;
	return ((len+2)/3)*4;
}

size_t fmt_base64(char* dest,const char* src,size_t len) {
  register const unsigned char* s=(const unsigned char*) src;
  unsigned short bits=0,temp=0;
  size_t written=0,i;
  if (!dest) return (len>((size_t)-1)/2)?(size_t)-1:((len+2)/3)*4;
  for (i=0; i<len; ++i) {
    temp<<=8; temp+=s[i]; bits+=8;
    while (bits>6) {
      dest[written]=base64[((temp>>(bits-6))&63)];
      ++written; bits-=6;
    }
  }
  if (bits) {
    temp<<=(6-bits);
    dest[written]=base64[temp&63];
    ++written;
  }
  while (written&3) { dest[written]='='; ++written; }
  return written;
}


static inline int dec(unsigned char x) {
  if (x>='A' && x<='Z') return x-'A';
  if (x>='a' && x<='z') return x-'a'+26;
  if (x>='0' && x<='9') return x-'0'+26+26;
  switch (x) {
  case '-': return 62;
  case '_': return 63;
  default: return -1;
  }
}

size_t scan_base64(const char *src,char *dest,size_t *destlen) {
  unsigned short tmp=0,bits=0;
  register const unsigned char* s=(const unsigned char*) src;
  const char* orig=dest;
  for (;;) {
    int a=dec(*s);
    if (a<0) {
      while (*s=='=') ++s;
      break;
    }
    tmp=(tmp<<6)|a; bits+=6;
    ++s;
    if (bits>=8) {
      *dest=(tmp>>(bits-=8));
      ++dest;
    }
  }
  *destlen=dest-orig;
  return (const char*)s-src;
}