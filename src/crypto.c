#include "common.h"
mpz_t P, Q, G, H;
void put32(unsigned char *p, uint32_t v) {
    for (int i = 3; i >= 0; i--) {
        p[i] = (unsigned char)v;
        v >>= 8;
    }
}
uint32_t get32(const unsigned char *p) {
    uint32_t v = 0;
    for (int i = 0; i < 4; i++)
        v = (v << 8) | p[i];
    return v;
}
void put64(unsigned char *p, uint64_t v) {
    for (int i = 7; i >= 0; i--) {
        p[i] = (unsigned char)v;
        v >>= 8;
    }
}
uint64_t get64(const unsigned char *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++)
        v = (v << 8) | p[i];
    return v;
}
double now(clockid_t clk) {
    struct timespec t;
    CHECK(clock_gettime(clk, &t) == 0);
    return t.tv_sec + t.tv_nsec / 1e9;
}
void hash(const void *p, size_t n, unsigned char out[32]) {
    unsigned len = 0;
    CHECK(EVP_Digest(p, n, out, &len, EVP_sha256(), NULL) == 1 && len == 32);
}
void crypto_init(void) {
    mpz_inits(P, Q, G, H, NULL);
    CHECK(mpz_set_str(P,
                      "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B13"
                      "9B22514A08798E3404DDEF9519B3CD3A431B"
                      "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406"
                      "B7EDEE386BFB5A899FA5AE9F24117C4B1FE6"
                      "49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3"
                      "AD961C62F356208552BB9ED529077096966D"
                      "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07"
                      "A28FB5C55DF06F4C52C9DE2BCBF695581718"
                      "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",
                      16) == 0);
    mpz_sub_ui(Q, P, 1);
    mpz_fdiv_q_2exp(Q, Q, 1);
    mpz_set_ui(G, 2);
    unsigned char bytes[B];
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    CHECK(md);
    const char *label = "pi-meter-sim-v1/pedersen-h";
    CHECK(EVP_DigestInit_ex(md, EVP_shake256(), NULL) == 1);
    CHECK(EVP_DigestUpdate(md, label, strlen(label)) == 1);
    CHECK(EVP_DigestFinalXOF(md, bytes, B) == 1);
    EVP_MD_CTX_free(md);
    mpz_import(H, B, 1, 1, 1, 0, bytes);
    mpz_powm_ui(H, H, 2, P);
    mpz_t t;
    mpz_init(t);
    mpz_powm(t, H, Q, P);
    CHECK(mpz_cmp_ui(t, 1) == 0 && mpz_cmp_ui(H, 1) > 0);
    mpz_powm(t, G, Q, P);
    CHECK(mpz_cmp_ui(t, 1) == 0);
    mpz_clear(t);
}
void packz(unsigned char *out, const mpz_t z) {
    size_t n = 0;
    CHECK(mpz_sgn(z) >= 0 && mpz_sizeinbase(z, 2) <= B * 8);
    memset(out, 0, B);
    unsigned char tmp[B];
    mpz_export(tmp, &n, 1, 1, 1, 0, z);
    memcpy(out + B - n, tmp, n);
}
void unpackz(mpz_t out, const unsigned char *in) {
    mpz_import(out, B, 1, 1, 1, 0, in);
}
void scalar_random(mpz_t v) {
    unsigned char b[B];
    do {
        CHECK(RAND_priv_bytes(b, B) == 1);
        b[0] &= 0x7f;
        unpackz(v, b);
    } while (mpz_cmp(v, Q) >= 0);
    OPENSSL_cleanse(b, B);
}
void commitment(mpz_t out, const mpz_t value, const mpz_t blind) {
    mpz_t t;
    mpz_init(t); /* GMP powm_sec requires a positive exponent. */
    if (mpz_sgn(value))
        mpz_powm_sec(out, G, value, P);
    else
        mpz_set_ui(out, 1);
    if (mpz_sgn(blind))
        mpz_powm_sec(t, H, blind, P);
    else
        mpz_set_ui(t, 1);
    mpz_mul(out, out, t);
    mpz_mod(out, out, P);
    mpz_clear(t);
}
void keygen(unsigned char sk[32], unsigned char pk[32]) {
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    EVP_PKEY *k = NULL;
    CHECK(c && EVP_PKEY_keygen_init(c) > 0 && EVP_PKEY_keygen(c, &k) > 0);
    size_t n = 32;
    CHECK(EVP_PKEY_get_raw_private_key(k, sk, &n) > 0);
    n = 32;
    CHECK(EVP_PKEY_get_raw_public_key(k, pk, &n) > 0);
    EVP_PKEY_free(k);
    EVP_PKEY_CTX_free(c);
}
void derive(const unsigned char sk[32], const unsigned char pk[32], int src, int dst,
            const unsigned char runid[32], unsigned char out[32]) {
    EVP_PKEY *a = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, sk, 32),
             *b = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, pk, 32);
    CHECK(a && b);
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new(a, NULL);
    unsigned char secret[32], info[16] = "meter-v1";
    size_t n = 32;
    CHECK(c && EVP_PKEY_derive_init(c) > 0 && EVP_PKEY_derive_set_peer(c, b) > 0 &&
          EVP_PKEY_derive(c, secret, &n) > 0);
    EVP_PKEY_CTX_free(c);
    EVP_PKEY_free(a);
    EVP_PKEY_free(b);
    put32(info + 8, (uint32_t)src);
    put32(info + 12, (uint32_t)dst);
    c = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    n = 32;
    CHECK(c && EVP_PKEY_derive_init(c) > 0 && EVP_PKEY_CTX_set_hkdf_md(c, EVP_sha256()) > 0 &&
          EVP_PKEY_CTX_set1_hkdf_salt(c, runid, 32) > 0 &&
          EVP_PKEY_CTX_set1_hkdf_key(c, secret, 32) > 0 &&
          EVP_PKEY_CTX_add1_hkdf_info(c, info, 16) > 0 && EVP_PKEY_derive(c, out, &n) > 0);
    EVP_PKEY_CTX_free(c);
    OPENSSL_cleanse(secret, 32);
}
int seal(const unsigned char key[32], const unsigned char *header, const unsigned char *plain,
         int n, unsigned char *wire) {
    unsigned char nonce[12];
    memcpy(nonce, header + 4, 4);
    memcpy(nonce + 4, header + 24, 8);
    memcpy(wire, header, HEADER);
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    int m = 0, t = 0;
    CHECK(c && n <= CAP - HEADER - TAG);
    CHECK(EVP_EncryptInit_ex(c, EVP_aes_256_gcm(), NULL, key, nonce) == 1);
    CHECK(EVP_EncryptUpdate(c, NULL, &m, header, HEADER) == 1);
    CHECK(EVP_EncryptUpdate(c, wire + HEADER, &m, plain, n) == 1);
    CHECK(EVP_EncryptFinal_ex(c, wire + HEADER + m, &t) == 1);
    CHECK(EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_GET_TAG, TAG, wire + HEADER + n) == 1);
    EVP_CIPHER_CTX_free(c);
    return HEADER + n + TAG;
}
int unseal(const unsigned char key[32], const unsigned char *wire, int n, unsigned char *plain) {
    if (n < HEADER + TAG)
        return -1;
    int m = 0, t = 0, len = n - HEADER - TAG;
    unsigned char nonce[12];
    memcpy(nonce, wire + 4, 4);
    memcpy(nonce + 4, wire + 24, 8);
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    CHECK(c);
    CHECK(EVP_DecryptInit_ex(c, EVP_aes_256_gcm(), NULL, key, nonce) == 1);
    CHECK(EVP_DecryptUpdate(c, NULL, &m, wire, HEADER) == 1);
    CHECK(EVP_DecryptUpdate(c, plain, &m, wire + HEADER, len) == 1);
    CHECK(EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_TAG, TAG, (void *)(wire + HEADER + len)) == 1);
    int ok = EVP_DecryptFinal_ex(c, plain + m, &t);
    EVP_CIPHER_CTX_free(c);
    if (ok != 1) {
        OPENSSL_cleanse(plain, len);
        return -1;
    }
    return len;
}
/* Recover BOTH coefficients, not just F(0), using degree k-1 Lagrange bases. */
void interpolate01(mpz_t value, mpz_t blind, mpz_t *ys, const int *xs, int k) {
    mpz_t *poly = malloc(sizeof(mpz_t) * (size_t)k);
    CHECK(poly);
    for (int i = 0; i < k; i++)
        mpz_init(poly[i]);
    mpz_t den, tmp, inv;
    mpz_inits(den, tmp, inv, NULL);
    mpz_set_ui(value, 0);
    mpz_set_ui(blind, 0);
    for (int j = 0; j < k; j++) {
        for (int a = 0; a < k; a++) {
            mpz_set_ui(poly[a], 0);
        }
        mpz_set_ui(poly[0], 1);
        mpz_set_ui(den, 1);
        int degree = 0;
        for (int m = 0; m < k; m++)
            if (m != j) {
                for (int d = degree + 1; d >= 0; d--) {
                    mpz_mul_si(tmp, poly[d], -xs[m]);
                    if (d > 0)
                        mpz_add(tmp, tmp, poly[d - 1]);
                    mpz_mod(poly[d], tmp, Q);
                }
                degree++;
                mpz_mul_si(den, den, xs[j] - xs[m]);
                mpz_mod(den, den, Q);
            }
        CHECK(mpz_invert(inv, den, Q) != 0);
        mpz_mul(tmp, ys[j], inv);
        mpz_mod(tmp, tmp, Q);
        mpz_addmul(value, tmp, poly[0]);
        mpz_addmul(blind, tmp, poly[1]);
    }
    mpz_mod(value, value, Q);
    mpz_mod(blind, blind, Q);
    for (int i = 0; i < k; i++)
        mpz_clear(poly[i]);
    free(poly);
    mpz_clears(den, tmp, inv, NULL);
}
