/*
 * Libgcrypt (C) — protocolo publicado.
 *
 * DIVERGÊNCIA ARTIGO × CÓDIGO DOS AUTORES:
 *   Preenchimento declarado no artigo: ver a Tabela 2 do artigo.
 *   Código dos autores: C/gcrypt/load/main.c cifra com "(data (flags raw) (value %b))" — RSA sem preenchimento —
 *   sobre MESSAGE_SIZE = 190 bytes de um buffer em que só 90 vêm do arquivo; C/gcrypt/api/main.c usa (flags pkcs1).
 * Decisão: o padrão (--padding oaep-sha1) segue o ARTIGO (OAEP com o hash padrão do Libgcrypt, SHA-1, coerente com
 * o limite de mensagem declarado na Tabela 2 do artigo). A variante --padding raw reproduz o CÓDIGO e é coletada só como
 * variante suplementar (c_libgcrypt_raw), fora da comparação principal.
 *
 * Chaves: S-expressions (private.sexp/public.sexp) derivadas da mesma chave OpenSSL (ver tools/keys.py).
 * Padrão de chamada: S-expression de dados construída a cada operação, gcry_pk_encrypt/gcry_pk_decrypt (como os
 * autores). Geração: gcry_pk_genkey com "(genkey (rsa (nbits ...)))" (e = 65537, padrão do Libgcrypt).
 * Inicialização: gcry_check_version + GCRYCTL_INITIALIZATION_FINISHED (os autores não inicializavam; a
 * documentação do Libgcrypt exige — sem efeito sobre o algoritmo). A memória segura fica no padrão.
 */
#include <gcrypt.h>

#include "../common/harness.h"

static gcry_sexp_t pub_key, priv_key;
static int raw_mode;

static const char *meta(const h_args *a) {
    static char buf[512];
    snprintf(buf, sizeof buf,
             "{\"id\":\"c_libgcrypt\",\"language\":\"C\",\"library\":\"Libgcrypt\",\"library_version\":\"%s\","
             "\"runtime\":\"gcc %s\",\"padding\":\"%s\"}",
             gcry_check_version(NULL), __VERSION__, (a->padding && !strcmp(a->padding, "raw")) ? "raw" : "oaep-sha1");
    return buf;
}

static gcry_sexp_t read_sexp(const h_args *a, const char *file) {
    char path[1024];
    size_t n;
    h_keypath(path, sizeof path, a, file);
    unsigned char *b = h_read(path, &n);
    gcry_sexp_t s;
    if (gcry_sexp_new(&s, b, n, 1)) h_die(5, "S-expression da chave inválida");
    free(b);
    return s;
}

static void load(const h_args *a) {
    raw_mode = a->padding && !strcmp(a->padding, "raw");
    if (a->padding && !raw_mode && strcmp(a->padding, "oaep-sha1")) h_die(2, "Libgcrypt: oaep-sha1 ou raw");
    pub_key = read_sexp(a, "public.sexp");
    priv_key = read_sexp(a, "private.sexp");
    if (gcry_pk_testkey(priv_key)) h_die(5, "chave privada rejeitada por gcry_pk_testkey");
}

static int enc(const unsigned char *m, size_t ml, unsigned char **out, size_t *ol) {
    gcry_sexp_t data, cipher;
    int rc = raw_mode ? gcry_sexp_build(&data, NULL, "(data (flags raw) (value %b))", (int)ml, m)
                      : gcry_sexp_build(&data, NULL, "(data (flags oaep) (value %b))", (int)ml, m);
    if (rc) return 1;
    rc = gcry_pk_encrypt(&cipher, data, pub_key);
    gcry_sexp_release(data);
    if (rc) return 1;
    gcry_sexp_t a = gcry_sexp_find_token(cipher, "a", 0);
    size_t n = 0;
    const char *v = a ? gcry_sexp_nth_data(a, 1, &n) : NULL;
    if (!v) { gcry_sexp_release(a); gcry_sexp_release(cipher); return 1; }
    /* O Libgcrypt devolve o MPI: pode vir com 00 inicial (bit alto ligado) ou mais curto. Normaliza para
       exatamente k bytes (I2OSP, RFC 8017), o formato dos demais textos cifrados. */
    size_t k = (gcry_pk_get_nbits(pub_key) + 7) / 8;
    while (n > k && v[0] == 0) { v++; n--; }
    if (n > k) { gcry_sexp_release(a); gcry_sexp_release(cipher); return 1; }
    *out = (unsigned char *)calloc(k, 1);
    memcpy(*out + (k - n), v, n);
    *ol = k;
    gcry_sexp_release(a);
    gcry_sexp_release(cipher);
    return 0;
}

static int dec(const unsigned char *c, size_t cl, unsigned char **out, size_t *ol) {
    gcry_sexp_t cipher, plain;
    int rc = raw_mode ? gcry_sexp_build(&cipher, NULL, "(enc-val (flags raw) (rsa (a %b)))", (int)cl, c)
                      : gcry_sexp_build(&cipher, NULL, "(enc-val (flags oaep) (rsa (a %b)))", (int)cl, c);
    if (rc) return 1;
    rc = gcry_pk_decrypt(&plain, cipher, priv_key);
    gcry_sexp_release(cipher);
    if (rc) return 1;
    /* OAEP: (value <bytes>); raw: o MPI como único elemento ou (value ...) conforme a versão */
    gcry_sexp_t v = gcry_sexp_find_token(plain, "value", 0);
    size_t n = 0;
    const char *d = v ? gcry_sexp_nth_data(v, 1, &n) : gcry_sexp_nth_data(plain, 0, &n);
    if (!d) { gcry_sexp_release(v); gcry_sexp_release(plain); return 1; }
    while (raw_mode && n > 0 && d[0] == 0) { d++; n--; }  /* MPI: zeros à esquerda */
    *out = (unsigned char *)malloc(n ? n : 1);
    memcpy(*out, d, n);
    *ol = n;
    gcry_sexp_release(v);
    gcry_sexp_release(plain);
    return 0;
}

static gcry_sexp_t gen_key;

static void keygen(int bits) {
    gcry_sexp_t spec, key;
    char digits[16], s[64];
    snprintf(digits, sizeof digits, "%d", bits);
    snprintf(s, sizeof s, "(genkey (rsa (nbits %zu:%s)))", strlen(digits), digits); /* ex.: (nbits 4:2048) */
    if (gcry_sexp_new(&spec, s, 0, 1) || gcry_pk_genkey(&key, spec)) h_die(5, "gcry_pk_genkey");
    gcry_sexp_release(spec);
    gen_key = key;
}

static void keyinfo(unsigned long *e, int *nbits) {
    gcry_sexp_t pub = gcry_sexp_find_token(gen_key, "public-key", 0);
    gcry_sexp_t et = pub ? gcry_sexp_find_token(pub, "e", 0) : NULL;
    gcry_mpi_t em = et ? gcry_sexp_nth_mpi(et, 1, GCRYMPI_FMT_USG) : NULL;
    unsigned int v = 0;
    if (!em || gcry_mpi_get_ui(&v, em)) h_die(5, "expoente da chave gerada");
    *e = v;
    *nbits = (int)gcry_pk_get_nbits(pub);
    gcry_mpi_release(em);
    gcry_sexp_release(et);
    gcry_sexp_release(pub);
    gcry_sexp_release(gen_key);
    gen_key = NULL;
}

int main(int argc, char **argv) {
    /* Memória segura: padrão do Libgcrypt (não desligada), como no programa dos autores. */
    if (!gcry_check_version(GCRYPT_VERSION)) h_die(5, "versão do Libgcrypt incompatível");
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
    h_ops ops = {meta, load, enc, dec, keygen, keyinfo};
    return h_main(argc, argv, &ops);
}
