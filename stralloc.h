#ifndef STRALLOC_H
#define STRALLOC_H

/* stralloc is the internal data structure all functions are working on.
 * s is the string.
 * len is the used length of the string.
 * a is the allocated length of the string.
 */

typedef struct stralloc {
  char* s;
  size_t len;
  size_t a;
} stralloc;

/* stralloc_init will initialize a stralloc.
 * Previously allocated memory will not be freed; use stralloc_free for
 * that.  To assign an empty string, use stralloc_copys(sa,""). */
void stralloc_init(stralloc* sa);

/* stralloc_ready makes sure that sa has enough space allocated to hold
 * len bytes: If sa is not allocated, stralloc_ready allocates at least
 * len bytes of space, and returns 1. If sa is already allocated, but
 * not enough to hold len bytes, stralloc_ready allocates at least len
 * bytes of space, copies the old string into the new space, frees the
 * old space, and returns 1. Note that this changes sa.s.  If the
 * allocation fails, stralloc_ready leaves sa alone and returns 0. */
int stralloc_ready(stralloc* sa,size_t len);

/* stralloc_readyplus is like stralloc_ready except that, if sa is
 * already allocated, stralloc_readyplus adds the current length of sa
 * to len. */
int stralloc_readyplus(stralloc* sa,size_t len);

/* stralloc_copyb copies the string buf[0], buf[1], ..., buf[len-1] into
 * sa, allocating space if necessary, and returns 1. If it runs out of
 * memory, stralloc_copyb leaves sa alone and returns 0. */
int stralloc_copyb(stralloc* sa,const char* buf,size_t len);

/* stralloc_copys copies a \0-terminated string from buf into sa,
 * without the \0. It is the same as
 * stralloc_copyb(&sa,buf,str_len(buf)). */
int stralloc_copys(stralloc* sa,const char* buf);

/* stralloc_copy copies the string stored in sa2 into sa. It is the same
 * as stralloc_copyb(&sa,sa2.s,sa2.len). sa2 must already be allocated. */
int stralloc_copy(stralloc* sa,const stralloc* sa2);

/* stralloc_catb adds the string buf[0], buf[1], ... buf[len-1] to the
 * end of the string stored in sa, allocating space if necessary, and
 * returns 1. If sa is unallocated, stralloc_catb is the same as
 * stralloc_copyb. If it runs out of memory, stralloc_catb leaves sa
 * alone and returns 0. */
int stralloc_catb(stralloc* sa,const char* in,size_t len);

/* stralloc_cats is analogous to stralloc_copys */
int stralloc_cats(stralloc* sa,const char* in);

void stralloc_zero(stralloc* sa);

/* like stralloc_cats but can cat more than one string at once */
int stralloc_catm_internal(stralloc* sa,...);

#define stralloc_catm(sa,...) stralloc_catm_internal(sa,__VA_ARGS__,(char*)0)
#define stralloc_copym(sa,...) (stralloc_zero(sa), stralloc_catm_internal(sa,__VA_ARGS__,(char*)0))

/* stralloc_cat is analogous to stralloc_copy */
int stralloc_cat(stralloc* sa,stralloc* in);

/* stralloc_append adds one byte in[0] to the end of the string stored
 * in sa. It is the same as stralloc_catb(&sa,in,1). */
int stralloc_append(stralloc* sa,const char* in); /* beware: this takes a pointer to 1 char */

/* stralloc_starts returns 1 if the \0-terminated string in "in", without
 * the terminating \0, is a prefix of the string stored in sa. Otherwise
 * it returns 0. sa must already be allocated. */
int stralloc_starts(stralloc* sa,const char* in);

/* stralloc_diff returns negative, 0, or positive, depending on whether
 * a is lexicographically smaller than, equal to, or greater than the
 * string b. */
int stralloc_diff(const stralloc* a,const stralloc* b);

/* stralloc_diffs returns negative, 0, or positive, depending on whether
 * a is lexicographically smaller than, equal to, or greater than the
 * string b[0], b[1], ..., b[n]=='\0'. */
int stralloc_diffs(const stralloc* a,const char* b);

#define stralloc_equal(a,b) (!stralloc_diff((a),(b)))
#define stralloc_equals(a,b) (!stralloc_diffs((a),(b)))

/* stralloc_0 appends \0 */
#define stralloc_0(sa) stralloc_append(sa,"")

/* stralloc_catulong0 appends a '0' padded ASCII representation of in */
int stralloc_catulong0(stralloc* sa,unsigned long int in,size_t n);

/* stralloc_catlong0 appends a '0' padded ASCII representation of in */
int stralloc_catlong0(stralloc* sa,signed long int in,size_t n);

/* stralloc_free frees the storage associated with sa */
void stralloc_free(stralloc* sa);

#define stralloc_catlong(sa,l) (stralloc_catlong0((sa),(l),0))
#define stralloc_catuint0(sa,i,n) (stralloc_catulong0((sa),(i),(n)))
#define stralloc_catint0(sa,i,n) (stralloc_catlong0((sa),(i),(n)))
#define stralloc_catint(sa,i) (stralloc_catlong0((sa),(i),0))

/* remove last char.  Return removed byte as unsigned char (or -1 if stralloc was empty). */
int stralloc_chop(stralloc* sa);

/* remove trailing "\r\n", "\n" or "\r".  Return number of removed chars (0,1 or 2) */
int stralloc_chomp(stralloc* sa);

int stralloc_remove_whitespaces(stralloc* sa);

void byte_copy(void*, size_t, const void*);
int byte_diff(const void*, size_t, const void*);
int byte_equal_notimingattack(const void*, size_t,const void* );

void rand_mem(void* out, size_t len);

#endif