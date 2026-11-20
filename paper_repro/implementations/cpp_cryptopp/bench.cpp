/*
 * Crypto++ (C++) — protocolo publicado. Padrão conferido em C++/Crypto++/load/main.cpp dos autores (commit
 * 1b3ffe0), reimplementado de forma independente:
 *   - chaves em DER (formato exigido segundo o artigo, §3.2): BERDecode de
 *     public.der (SubjectPublicKeyInfo) e private.der (PKCS#8);
 *   - RSAES_OAEP_SHA (OAEP com SHA-1); a CADA operação os autores criavam um AutoSeededRandomPool e o
 *     Encryptor/Decryptor e passavam por StringSource/PK_EncryptorFilter — reproduzido aqui;
 *   - geração: InvertibleRSAFunction::GenerateRandomWithKeySize(rng, bits), cujo expoente padrão é 17
 *     (o que o artigo também observa, §4.2). Os autores também codificavam em DER e gravavam
 *     os arquivos dentro da medida; aqui mede-se só a geração, sem gravar arquivos.
 */
#include <cryptopp/cryptlib.h>
#include <cryptopp/files.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <cryptopp/rsa.h>

#include <string>

#include "../common/harness.h"

using namespace CryptoPP;

static RSA::PublicKey pub_key;
static RSA::PrivateKey priv_key;

static const char *meta(const h_args *) {
    static char buf[512];
    int v = CRYPTOPP_VERSION;
    snprintf(buf, sizeof buf,
             "{\"id\":\"cpp_cryptopp\",\"language\":\"C++\",\"library\":\"Crypto++\",\"library_version\":\"%d.%d.%d\","
             "\"runtime\":\"g++ %s\",\"padding\":\"oaep-sha1\",\"keygen_public_exponent\":17}",
             v / 100, (v / 10) % 10, v % 10, __VERSION__);
    return buf;
}

static void load(const h_args *a) {
    if (a->padding && strcmp(a->padding, "oaep-sha1")) h_die(2, "Crypto++: só oaep-sha1 (RSAES_OAEP_SHA)");
    char p[1024];
    try {
        h_keypath(p, sizeof p, a, "public.der");
        FileSource fu(p, true);
        pub_key.BERDecode(fu);
        h_keypath(p, sizeof p, a, "private.der");
        FileSource fp(p, true);
        priv_key.BERDecode(fp);
        AutoSeededRandomPool rng;
        if (!priv_key.Validate(rng, 3)) h_die(5, "Crypto++: chave privada inválida");
    } catch (const Exception &e) {
        fprintf(stderr, "erro Crypto++: %s\n", e.what());
        h_die(5, "carga de chaves");
    }
}

static int enc(const unsigned char *m, size_t ml, unsigned char **out, size_t *ol) {
    try {
        AutoSeededRandomPool rng;
        RSAES_OAEP_SHA_Encryptor e(pub_key);
        std::string c;
        StringSource(m, ml, true, new PK_EncryptorFilter(rng, e, new StringSink(c)));
        *out = (unsigned char *)malloc(c.size());
        memcpy(*out, c.data(), c.size());
        *ol = c.size();
        return 0;
    } catch (const Exception &) { return 1; }
}

static int dec(const unsigned char *c, size_t cl, unsigned char **out, size_t *ol) {
    try {
        AutoSeededRandomPool rng;
        RSAES_OAEP_SHA_Decryptor d(priv_key);
        std::string p;
        StringSource(c, cl, true, new PK_DecryptorFilter(rng, d, new StringSink(p)));
        *out = (unsigned char *)malloc(p.size() ? p.size() : 1);
        memcpy(*out, p.data(), p.size());
        *ol = p.size();
        return 0;
    } catch (const Exception &) { return 1; }
}

static RSA::PrivateKey gen_key;

static void keygen(int bits) {
    AutoSeededRandomPool rng;
    gen_key.GenerateRandomWithKeySize(rng, (unsigned int)bits);
    RSA::PublicKey pk(gen_key);
    (void)pk;
}

static void keyinfo(unsigned long *e, int *nbits) {
    *e = (unsigned long)gen_key.GetPublicExponent().ConvertToLong();
    *nbits = (int)gen_key.GetModulus().BitCount();
}

int main(int argc, char **argv) {
    h_ops ops = {meta, load, enc, dec, keygen, keyinfo};
    return h_main(argc, argv, &ops);
}
