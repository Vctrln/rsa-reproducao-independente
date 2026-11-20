/*
 * OpenSSL (C) — protocolo publicado. Padrão de chamada conferido em C/OpenSSL/load/main.c dos autores
 * (commit 1b3ffe0), reimplementado de forma independente:
 *   - chaves PEM carregadas com PEM_read_PUBKEY / PEM_read_PrivateKey;
 *   - cifração/decifração com um EVP_PKEY_CTX NOVO por operação, SEM definir o preenchimento
 *     (padrão do EVP = PKCS#1 v1.5; ver a Tabela 2 do artigo);
 *   - geração de chave com EVP_RSA_gen(bits) (os autores também gravavam os PEM em disco; aqui só a geração).
 */
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/rsa.h>

#include "../common/harness.h"

static EVP_PKEY *pub_key, *priv_key;

static const char *meta(const h_args *a) {
    static char buf[512];
    (void)a;
    snprintf(buf, sizeof buf,
             "{\"id\":\"c_openssl\",\"language\":\"C\",\"library\":\"OpenSSL\",\"library_version\":\"%s\","
             "\"runtime\":\"gcc %s\",\"padding\":\"pkcs1v15\"}",
             OpenSSL_version(OPENSSL_VERSION), __VERSION__);
    return buf;
}

static EVP_PKEY *read_pem(const h_args *a, const char *file, int priv) {
    char path[1024];
    h_keypath(path, sizeof path, a, file);
    FILE *f = fopen(path, "r");
    if (!f) h_die(5, "abrir chave PEM");
    EVP_PKEY *k = priv ? PEM_read_PrivateKey(f, NULL, NULL, NULL) : PEM_read_PUBKEY(f, NULL, NULL, NULL);
    fclose(f);
    if (!k) h_die(5, "ler chave PEM");
    return k;
}

static void load(const h_args *a) {
    if (a->padding && strcmp(a->padding, "pkcs1v15")) h_die(2, "OpenSSL (C): só pkcs1v15 (padrão do EVP)");
    pub_key = read_pem(a, "public.pem", 0);
    priv_key = read_pem(a, "private.pem", 1);
}

static int enc(const unsigned char *m, size_t ml, unsigned char **out, size_t *ol) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pub_key, NULL);
    size_t n = 0;
    int ok = ctx && EVP_PKEY_encrypt_init(ctx) > 0 && EVP_PKEY_encrypt(ctx, NULL, &n, m, ml) > 0;
    if (ok) {
        *out = (unsigned char *)malloc(n);
        ok = EVP_PKEY_encrypt(ctx, *out, &n, m, ml) > 0;
        *ol = n;
    }
    EVP_PKEY_CTX_free(ctx);
    return ok ? 0 : 1;
}

static int dec(const unsigned char *c, size_t cl, unsigned char **out, size_t *ol) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(priv_key, NULL);
    size_t n = 0;
    int ok = ctx && EVP_PKEY_decrypt_init(ctx) > 0 && EVP_PKEY_decrypt(ctx, NULL, &n, c, cl) > 0;
    if (ok) {
        *out = (unsigned char *)malloc(n);
        ok = EVP_PKEY_decrypt(ctx, *out, &n, c, cl) > 0;
        *ol = n;
    }
    EVP_PKEY_CTX_free(ctx);
    return ok ? 0 : 1;
}

static EVP_PKEY *gen_key;

static void keygen(int bits) {
    gen_key = EVP_RSA_gen((unsigned int)bits);
    if (!gen_key) h_die(5, "EVP_RSA_gen");
}

static void keyinfo(unsigned long *e, int *nbits) {
    BIGNUM *bn = NULL;
    if (EVP_PKEY_get_bn_param(gen_key, "e", &bn) <= 0) h_die(5, "expoente da chave gerada");
    *e = BN_get_word(bn);
    *nbits = EVP_PKEY_get_bits(gen_key);
    BN_free(bn);
    EVP_PKEY_free(gen_key);
    gen_key = NULL;
}

int main(int argc, char **argv) {
    h_ops ops = {meta, load, enc, dec, keygen, keyinfo};
    return h_main(argc, argv, &ops);
}
