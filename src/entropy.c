#include "entropy.h"
#include <math.h>
#include <ctype.h>

double shannon_entropy_bits(const char *s, size_t len)
{
    if (len == 0) return 0.0;

    size_t freq[256] = {0};
    for (size_t i = 0; i < len; i++)
        freq[(unsigned char)s[i]]++;

    double bits = 0.0;
    for (int i = 0; i < 256; i++) {
        if (!freq[i]) continue;
        double p = (double)freq[i] / (double)len;
        bits -= p * log2(p);
    }
    return bits;
}

int charset_pool(const char *s, size_t len)
{
    int lower = 0, upper = 0, digit = 0, symbol = 0;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)s[i];
        if (islower(c))      lower  = 1;
        else if (isupper(c)) upper  = 1;
        else if (isdigit(c)) digit  = 1;
        else                 symbol = 1;
    }
    int pool = 0;
    if (lower)  pool += 26;
    if (upper)  pool += 26;
    if (digit)  pool += 10;
    if (symbol) pool += 33;   /* printable ASCII punctuation, as in `entropy` */
    return pool ? pool : 1;
}

double naive_entropy_bits(const char *s, size_t len)
{
    if (len == 0) return 0.0;
    int pool = charset_pool(s, len);
    return (double)len * log2((double)pool);
}
