/*
 * Botan (C++) — protocolo publicado. Padrão conferido em C++/Botan/load/main.cpp dos autores (commit 1b3ffe0),
 * reimplementado de forma independente:
 *   - chaves: PKCS8::load_key / X509::load_key de PEM;
 *   - PK_Encryptor_EME e PK_Decryptor_EME com "OAEP(SHA-256)" criados UMA vez (fora do laço), AutoSeeded_RNG;
 *   - geração: RSA_PrivateKey(rng, bits) (e = 65537, padrão do Botan).
 * DIVERGÊNCIA DE VERSÃO: os autores compilaram o Botan 3 a partir do git (-lbotan-3); aqui é o Botan 2.19.3 do
 * Ubuntu 24.04 (libbotan-2-dev). A API usada é a mesma; diferenças de desempenho entre 2.x e 3.x não são controladas.
 * Os autores mediam com Google Benchmark (Iterations(N)->Repetitions(5)); aqui, harness comum (ver CONTRACT.md).
 */
#include <botan/auto_rng.h>
#include <botan/data_src.h>
#include <botan/pkcs8.h>
#include <botan/pubkey.h>
#include <botan/rsa.h>
#include <botan/version.h>
#include <botan/x509_key.h>

#include <memory>
#include <string>

#include "../common/harness.h"

static std::unique_ptr<Botan::Private_Key> priv_key;
static std::unique_ptr<Botan::Public_Key> pub_key;
static std::unique_ptr<Botan::AutoSeeded_RNG> rng;
static std::unique_ptr<Botan::PK_Encryptor_EME> encryptor;
static std::unique_ptr<Botan::PK_Decryptor_EME> decryptor;

static const char *meta(const h_args *) {
    static std::string s;
    s = std::string("{\"id\":\"cpp_botan\",\"language\":\"C++\",\"library\":\"Botan\",\"library_version\":\"") +
        Botan::short_version_string() + "\",\"runtime\":\"g++ " + __VERSION__ + "\",\"padding\":\"oaep-sha256\"}";
    return s.c_str();
}

static void load(const h_args *a) {
    if (a->padding && strcmp(a->padding, "oaep-sha256")) h_die(2, "Botan: só oaep-sha256 (código dos autores)");
    char p[1024];
    rng.reset(new Botan::AutoSeeded_RNG);
    try {
        h_keypath(p, sizeof p, a, "private.pem");
        Botan::DataSource_Stream ps(p);
        priv_key = Botan::PKCS8::load_key(ps);
        h_keypath(p, sizeof p, a, "public.pem");
        Botan::DataSource_Stream us(p);
        pub_key.reset(Botan::X509::load_key(us));
        encryptor.reset(new Botan::PK_Encryptor_EME(*pub_key, *rng, "OAEP(SHA-256)"));
        decryptor.reset(new Botan::PK_Decryptor_EME(*priv_key, *rng, "OAEP(SHA-256)"));
    } catch (const std::exception &e) {
        fprintf(stderr, "erro Botan: %s\n", e.what());
        h_die(5, "carga de chaves");
    }
}

static int enc(const unsigned char *m, size_t ml, unsigned char **out, size_t *ol) {
    try {
        std::vector<uint8_t> c = encryptor->encrypt(m, ml, *rng);
        *out = (unsigned char *)malloc(c.size());
        memcpy(*out, c.data(), c.size());
        *ol = c.size();
        return 0;
    } catch (const std::exception &) { return 1; }
}

static int dec(const unsigned char *c, size_t cl, unsigned char **out, size_t *ol) {
    try {
        Botan::secure_vector<uint8_t> p = decryptor->decrypt(c, cl);
        *out = (unsigned char *)malloc(p.size() ? p.size() : 1);
        memcpy(*out, p.data(), p.size());
        *ol = p.size();
        return 0;
    } catch (const std::exception &) { return 1; }
}

static std::unique_ptr<Botan::RSA_PrivateKey> gen_key;

static void keygen(int bits) {
    Botan::AutoSeeded_RNG r;
    gen_key.reset(new Botan::RSA_PrivateKey(r, (size_t)bits));
}

static void keyinfo(unsigned long *e, int *nbits) {
    *e = (unsigned long)gen_key->get_e().to_u32bit();
    *nbits = (int)gen_key->key_length();
    gen_key.reset();
}

int main(int argc, char **argv) {
    h_ops ops = {meta, load, enc, dec, keygen, keyinfo};
    int rc = h_main(argc, argv, &ops);
    /* Libera os objetos do Botan ANTES dos destrutores estáticos da própria biblioteca (pool de memória
       travada); deixá-los para a destruição estática causava falha de segmentação na saída. */
    gen_key.reset();
    decryptor.reset();
    encryptor.reset();
    priv_key.reset();
    pub_key.reset();
    rng.reset();
    return rc;
}
