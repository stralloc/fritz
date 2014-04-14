#include <windows.h>
#include <stdlib.h>
#include "stralloc.h"

#define str_len strlen

void rand_mem(void* out, size_t len) {
  char* s=out;
  size_t i;
  for (i=0; i<len; ++i)
    s[i]=rand()%256;
}

// from libowfat (http://www.fefe.de)

/* byte_copy copies in[0] to out[0], in[1] to out[1], ... and in[len-1]
 * to out[len-1]. */
void byte_copy(void* out, size_t len, const void* in) {
  char* s=out;
  const char* t=in;
#if 0
  /* gcc 4.3.1 generates wrong code for this, so I'm switching to
   * simpler code */
  size_t i;
  for (i=0; i<len; ++i)
    s[i]=t[i];
#else
  const char* u=t+len;
  if (len>127) {
    while ((unsigned long)s&(sizeof(unsigned long)-1)) {
      *s=*t; ++s; ++t;
    }
    /* s (destination) is now unsigned long aligned */
#ifndef __i386__
    if (!((unsigned long)t&(sizeof(unsigned long)-1)))
#endif
      while (t+sizeof(unsigned long)<=u) {
	*(unsigned long*)s=*(unsigned long*)t;
	s+=sizeof(unsigned long); t+=sizeof(unsigned long);
      }
  }
  for (;;) {
    if (t==u) break; *s=*t; ++s; ++t;
    if (t==u) break; *s=*t; ++s; ++t;
    if (t==u) break; *s=*t; ++s; ++t;
    if (t==u) break; *s=*t; ++s; ++t;
  }
#endif
}

/* If you need to compare a password or a hash value, the timing of the
 * comparison function can give valuable clues to the attacker. Let's
 * say the password is 123456 and the attacker tries abcdef. If the
 * comparision function fails at the first byte without looking at the
 * other bytes, then the attacker can measure the difference in runtime
 * and deduce which byte was wrong, reducing the attack space from
 * exponential to polynomial. */
int byte_equal_notimingattack(const void* a, size_t len,const void* b) {
  size_t i;
  const unsigned char* x=(const unsigned char*)a;
  const unsigned char* y=(const unsigned char*)b;
  unsigned char res=0;
  for (i=0; i<len; ++i) {
    res |= (x[i]^y[i]);
  }
  return res==0;
}

/* byte_diff returns negative, 0, or positive, depending on whether the
 * string one[0], one[1], ..., one[len-1] is lexicographically smaller
 * than, equal to, or greater than the string one[0], one[1], ...,
 * one[len-1]. When the strings are different, byte_diff does not read
 * bytes past the first difference. */
int byte_diff(const void* a, size_t len, const void* b) {
#if 0
  /* this gets miscompiled by gcc 4.3.2 on x86_64 */
  register const unsigned char* s=a;
  register const unsigned char* t=b;
  register const unsigned char* u=t+len;
  register int j;
  j=0;
  for (;;) {
    if (t==u) break; if ((j=((unsigned int)*s-*t))) break; ++s; ++t;
    if (t==u) break; if ((j=((unsigned int)*s-*t))) break; ++s; ++t;
    if (t==u) break; if ((j=((unsigned int)*s-*t))) break; ++s; ++t;
    if (t==u) break; if ((j=((unsigned int)*s-*t))) break; ++s; ++t;
  }
  return j;
#else
  size_t i;
  for (i=0; i<len; ++i) {
    int r=((unsigned char*)a)[i] - ((unsigned char*)b)[i];
    if (r) return r;
  }
  return 0;
#endif
}

/* stralloc_append adds one byte in[0] to the end of the string stored
 * in sa. It is the same as stralloc_catb(&sa,in,1). */
int stralloc_append(stralloc *sa,const char *in) {
  if (stralloc_readyplus(sa,1)) {
    sa->s[sa->len]=*in;
    ++sa->len;
    return 1;
  }
  return 0;
}

int stralloc_cat(stralloc *sa,stralloc *sa2) {
  return stralloc_catb(sa,sa2->s,sa2->len);
}

/* stralloc_catb adds the string buf[0], buf[1], ... buf[len-1] to the
 * end of the string stored in sa, allocating space if necessary, and
 * returns 1. If sa is unallocated, stralloc_catb is the same as
 * stralloc_copyb. If it runs out of memory, stralloc_catb leaves sa
 * alone and returns 0. */
int stralloc_catb(stralloc *sa,const char *buf,size_t len) {
  if (stralloc_readyplus(sa,len)) {
    byte_copy(sa->s+sa->len,len,buf);
    sa->len+=len;
    return 1;
  }
  return 0;
}

int stralloc_cats(stralloc *sa,const char *buf) {
  return stralloc_catb(sa,buf,str_len(buf));
}

int stralloc_chomp(stralloc* sa) {
  size_t max=sa->len;
  if (max>0) {
    register char x;
    --max;
    x=sa->s[max];
    if (x=='\n' || x=='\r') {
      if (x=='\n' && max>1 && sa->s[max-1]=='\r') {
	sa->len-=2;
	return 2;
      }
      --sa->len;
      return 1;
    }
  }
  return 0;
}

int stralloc_remove_whitespaces(stralloc* sa) {
	size_t found = 0;
	unsigned int i;
	unsigned char c;

	for(i=0;i<sa->len;i++) {
		c = sa->s[i];
		switch(c) {
			case '\n':
			case '\r':
			case '\t':
			case ' ': found++; break;
			default: sa->s[i-found] = c; break;
		}
	}
	sa->len -= found;
	
	stralloc_0(sa);
	return found;
}

int stralloc_chop(stralloc* sa) {
  if (sa->len==0) return -1;
  --sa->len;
  return (unsigned char)(sa->s[sa->len]);
}

int stralloc_copy(stralloc *sa,const stralloc *sa2) {
  return stralloc_copyb(sa,sa2->s,sa2->len);
}

/* stralloc_copyb copies the string buf[0], buf[1], ..., buf[len-1] into
 * sa, allocating space if necessary, and returns 1. If it runs out of
 * memory, stralloc_copyb leaves sa alone and returns 0. */
int stralloc_copyb(stralloc *sa,const char *buf,size_t len) {
  if (stralloc_ready(sa,len)) {
    sa->len=len;
    byte_copy(sa->s,len,buf);
    return 1;
  }
  return 0;
}

int stralloc_copys(stralloc *sa,const char *buf) {
  return stralloc_copyb(sa,buf,str_len(buf));
}

int stralloc_diff(const stralloc* a,const stralloc* b) {
  register size_t i;
  register int j;
  for (i=0;;++i) {
    if (i==a->len) return i==b->len?0:-1; if (i==b->len) return 1;
    if ((j=((unsigned char)(a->s[i])-(unsigned char)(b->s[i])))) return j;
  }
  return j;
}

int stralloc_diffs(const stralloc* a,const char* b) {
  register size_t i;
  register int j;
  for (i=0;;++i) {
    if (i==a->len) return (!b[i])?0:-1; if (!b[i]) return 1;
    if ((j=((unsigned char)(a->s[i])-(unsigned char)(b[i])))) return j;
  }
  return j;
}

void stralloc_free(stralloc *sa) {
  if (sa->s) free(sa->s);
  sa->s=0;
}

void stralloc_init(stralloc* sa) {
  sa->s=0;
  sa->len=sa->a=0;
}

/* stralloc_ready makes sure that sa has enough space allocated to hold
 * len bytes: If sa is not allocated, stralloc_ready allocates at least
 * len bytes of space, and returns 1. If sa is already allocated, but
 * not enough to hold len bytes, stralloc_ready allocates at least len
 * bytes of space, copies the old string into the new space, frees the
 * old space, and returns 1. Note that this changes sa.s. */
int stralloc_ready(stralloc *sa,size_t len) {
  register size_t wanted=len+(len>>3)+30; /* heuristic from djb */
  if (!sa->s || sa->a<len) {
    register char* tmp;
    if (!(tmp=realloc(sa->s,wanted)))
      return 0;
    sa->a=wanted;
    sa->s=tmp;
  }
  return 1;
}

/* stralloc_readyplus is like stralloc_ready except that, if sa is
 * already allocated, stralloc_readyplus adds the current length of sa
 * to len. */
int stralloc_readyplus(stralloc *sa,size_t len) {
  if (sa->s) {
    if (sa->len + len < len) return 0;	/* catch integer overflow */
    return stralloc_ready(sa,sa->len+len);
  } else
    return stralloc_ready(sa,len);
}

int stralloc_starts(stralloc *sa,const char *in) {
  register size_t len=str_len(in);
  return (len<=sa->len && !byte_diff(sa->s,len,in));
}

void stralloc_zero(stralloc* sa) {
  sa->len=0;
}
