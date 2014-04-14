#ifndef BASE64_H
#define BASE64_H

size_t scan_base64(const char *src,char *dest, size_t *destlen);
size_t fmt_base64(char* dest,const char* src, size_t len);
size_t base64_len(size_t len);

#define BASE64_NORMAL 0
#define BASE64_IGNORE_WHITESPACE 1
int isBase64(const char *str, unsigned int param);

#endif