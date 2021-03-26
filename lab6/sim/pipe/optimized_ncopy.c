// This file includes an optimized version of ncopy.c
#include <stdio.h>

typedef word_t word_t;

word_t src[8], dst[8];

word_t ncopy(word_t *src, word_t *dst, word_t len)
{
    word_t count = 0;
    word_t val;

    while((len -= 8) >= 0){
        val = *src++;
	    *dst++ = val;
        if(val > 0) count++;
        val = *src++;
	    *dst++ = val;
        if(val > 0) count++;
        val = *src++;
	    *dst++ = val;
        if(val > 0) count++;
        val = *src++;
	    *dst++ = val;
        if(val > 0) count++;
        val = *src++;
	    *dst++ = val;
        if(val > 0) count++;
        val = *src++;
	    *dst++ = val;
        if(val > 0) count++;
        val = *src++;
	    *dst++ = val;
        if(val > 0) count++;
        val = *src++;
	    *dst++ = val;
        if(val > 0) count++;
    }

    len += 8;
    while(--len >= 0){
        val = *src++;
	    *dst++ = val;
        if(val > 0) count++;
    }

    return count;
}

int main()
{
    word_t i, count;

    for (i=0; i<8; i++)
	src[i]= i+1;
    count = ncopy(src, dst, 8);
    printf ("count=%d\n", count);
    exit(0);
}


