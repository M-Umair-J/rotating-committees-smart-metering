#ifndef COMMON_H
#define COMMON_H
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <gmp.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/crypto.h>
#define MAXN 64
#define B 256
#define CAP 1024
#define HEADER 32
#define TAG 16
#define CHECK(x)                                                                                   \
    do {                                                                                           \
        if (!(x)) {                                                                                \
            fprintf(stderr, "Fatal: %s (%s:%d)\n", #x, __FILE__, __LINE__);                        \
            exit(2);                                                                               \
        }                                                                                          \
    } while (0)
extern mpz_t P, Q, G, H;
void crypto_init(void);
void scalar_random(mpz_t v);
void commitment(mpz_t out, const mpz_t value, const mpz_t blind);
void packz(unsigned char *out, const mpz_t z);
void unpackz(mpz_t out, const unsigned char *in);
void hash(const void *p, size_t n, unsigned char out[32]);
void put32(unsigned char *p, uint32_t v);
uint32_t get32(const unsigned char *p);
void put64(unsigned char *p, uint64_t v);
uint64_t get64(const unsigned char *p);
double now(clockid_t clk);
void keygen(unsigned char sk[32], unsigned char pk[32]);
void derive(const unsigned char sk[32], const unsigned char pk[32], int src, int dst,
            const unsigned char runid[32], unsigned char out[32]);
int seal(const unsigned char key[32], const unsigned char *header, const unsigned char *plain,
         int n, unsigned char *wire);
int unseal(const unsigned char key[32], const unsigned char *wire, int n, unsigned char *plain);
void interpolate01(mpz_t value, mpz_t blind, mpz_t *ys, const int *xs, int k);
#endif
