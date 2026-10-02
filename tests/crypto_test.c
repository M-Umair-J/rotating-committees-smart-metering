#include "common.h"
int main(void) {
    crypto_init();
    CHECK(mpz_sizeinbase(P, 2) == 2048);
    CHECK(mpz_probab_prime_p(P, 20) > 0 && mpz_probab_prime_p(Q, 20) > 0);
    mpz_t y[MAXN], co[MAXN], v, z, t, c1, c2, c3, a, b;
    mpz_inits(v, z, t, c1, c2, c3, a, b, NULL);
    int xs[MAXN];
    for (int i = 0; i < MAXN; i++) {
        mpz_init(y[i]);
        mpz_init(co[i]);
    }
    /* Nonconsecutive coordinates, varying thresholds, random coefficients. */
    for (int k = 2; k <= 10; k++)
        for (int trial = 0; trial < 5; trial++) {
            mpz_set_ui(co[0], 10 + trial);
            for (int d = 1; d < k; d++)
                scalar_random(co[d]);
            for (int j = 0; j < k; j++) {
                xs[j] = 2 * j + 3;
                mpz_set_ui(y[j], 0);
                for (int d = k - 1; d >= 0; d--) {
                    mpz_mul_ui(y[j], y[j], xs[j]);
                    mpz_add(y[j], y[j], co[d]);
                    mpz_mod(y[j], y[j], Q);
                }
            }
            interpolate01(v, z, y, xs, k);
            CHECK(mpz_cmp(v, co[0]) == 0 && mpz_cmp(z, co[1]) == 0);
        }
    mpz_set_ui(a, 5);
    mpz_set_ui(b, 7);
    commitment(c1, a, b);
    mpz_set_ui(a, 12);
    mpz_set_ui(b, 9);
    commitment(c2, a, b);
    mpz_mul(c3, c1, c2);
    mpz_mod(c3, c3, P);
    mpz_set_ui(a, 17);
    mpz_set_ui(b, 16);
    commitment(t, a, b);
    CHECK(mpz_cmp(c3, t) == 0);
    mpz_powm_ui(c3, c1, 98, P);
    mpz_set_ui(a, 490);
    mpz_set_ui(b, 686);
    commitment(t, a, b);
    CHECK(mpz_cmp(c3, t) == 0);
    unsigned char sk1[32], sk2[32], pk1[32], pk2[32], key1[32], key2[32], run[32] = {0};
    keygen(sk1, pk1);
    keygen(sk2, pk2);
    derive(sk1, pk2, 1, 2, run, key1);
    derive(sk2, pk1, 1, 2, run, key2);
    CHECK(!memcmp(key1, key2, 32));
    unsigned char h[HEADER] = {0}, plain[B], wire[CAP], back[CAP];
    put32(h, 4);
    put32(h + 4, 1);
    put32(h + 8, 2);
    put64(h + 24, 1);
    CHECK(RAND_bytes(plain, B) == 1);
    int n = seal(key1, h, plain, B, wire);
    CHECK(unseal(key2, wire, n, back) == B && !memcmp(plain, back, B));
    wire[HEADER] ^= 1;
    CHECK(unseal(key2, wire, n, back) < 0);
    wire[HEADER] ^= 1;
    wire[12] ^= 1;
    CHECK(unseal(key2, wire, n, back) < 0);
    /* Fixed independent known-answer supplied by Python in integration tests. */
    mpz_set_ui(a, 5);
    mpz_set_ui(b, 7);
    commitment(t, a, b);
    printf("commit_5_7=");
    mpz_out_str(stdout, 16, t);
    puts("\nCrypto tests PASS");
    return 0;
}
