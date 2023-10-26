#ifndef _RIPEMD160_H_
#define _RIPEMD160_H_

#include <stdint.h>

typedef struct {
    uint64_t length;
    union {
        uint32_t w[16];
        uint8_t b[64];
    } buf;
    uint32_t h[5];
    uint8_t bufpos;
} ripemd160_state;

void ripemd160_init(ripemd160_state *self);
void ripemd160(const unsigned char *in, unsigned long length, unsigned char *out);
void ripemd160_done(ripemd160_state *self, unsigned char *out);
void ripemd160(const unsigned char *in, unsigned long length, unsigned char *out);

#endif
