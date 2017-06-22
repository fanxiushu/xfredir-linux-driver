///by fanxiushu 2016-08-10
#include "common.h"

///计算字符串的哈希值，copy from internet
unsigned long hash_string(const char *s) 
{
	unsigned char* str = (unsigned char*)s;
	unsigned long hash = 5381;
	int c;

	while ( (c = *str++) != 0 ) {
		hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
	}

	return hash;
}

