/*
 * Harness comum (C e C++) do protocolo publicado. Implementa o CONTRATO das 12 implementações
 * (paper_repro/implementations/CONTRACT.md):
 *
 *   <prog> version
 *   <prog> bench   --keydir D --bits B --msg M --sets 10,100,1000,10000 --keygen-rounds R [--padding P]
 *   <prog> keygen  --bits B --keygen-rounds R            -> experimento independente de geração de chaves
 *   <prog> encrypt --keydir D --bits B --msg M [--padding P]      -> hex do texto cifrado (saída 3 se não cifrar)
 *   <prog> decrypt --keydir D --bits B --in ARQ_HEX [--padding P] -> hex do texto decifrado
 *   <prog> hold    --keydir D --bits B --msg M [--padding P]      -> carrega chaves, cifra+decifra 1x,
 *                                                                    imprime "READY <hex>" e espera uma linha no stdin
 * Saída de `bench` (CSV, uma linha por registro):
 *   meta,<json>
 *   keygen,<bits>,<rodada>,<segundos>,<expoente público gerado>,<bits do módulo gerado>
 *   set,<N>,<encrypt|decrypt>,<n>,<média_s>,<dp_pop_s>,<mín_s>,<máx_s>,<total_s>
 *   done
 * Cada operação é cronometrada individualmente (relógio monotônico), como no código C/JS dos autores;
 * média e desvio padrão POPULACIONAL por conjunto, como em calcular_desvio_padrao() do código C dos autores.
 * A verificação (decifrado == mensagem) é feita a cada iteração, fora do cronômetro; divergência aborta (saída 4).
 *
 * Implementação independente: nenhum código do repositório dos autores foi copiado (ele não tem arquivo de licença).
 */
#ifndef PAPER_HARNESS_H
#define PAPER_HARNESS_H

#include <errno.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

typedef struct {
    const char *mode, *keydir, *msg, *sets, *padding, *in;
    int bits, keygen_rounds;
} h_args;

static inline double h_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

/* _exit (sem destrutores estáticos): bibliotecas C++ como o Botan podem falhar se destruídas fora de ordem,
   o que trocaria o código de saída documentado por uma falha de segmentação. */
static inline void h_die(int code, const char *msg) {
    fprintf(stderr, "erro: %s\n", msg);
    fflush(stdout);
    fflush(stderr);
    _exit(code);
}

static inline h_args h_parse(int argc, char **argv) {
    h_args a;
    memset(&a, 0, sizeof a);
    a.keygen_rounds = 1;
    if (argc < 2) h_die(2, "uso: <version|bench|encrypt|decrypt|hold> [opções]");
    a.mode = argv[1];
    for (int i = 2; i < argc; i++) {
        const char *o = argv[i];
        if (i + 1 >= argc) h_die(2, "opção sem valor");
        const char *v = argv[++i];
        if (!strcmp(o, "--keydir")) a.keydir = v;
        else if (!strcmp(o, "--bits")) a.bits = atoi(v);
        else if (!strcmp(o, "--msg")) a.msg = v;
        else if (!strcmp(o, "--sets")) a.sets = v;
        else if (!strcmp(o, "--padding")) a.padding = v;
        else if (!strcmp(o, "--in")) a.in = v;
        else if (!strcmp(o, "--keygen-rounds")) a.keygen_rounds = atoi(v);
        else h_die(2, "opção desconhecida");
    }
    if (strcmp(a.mode, "version") && (a.bits != 2048 && a.bits != 3072 && a.bits != 4096))
        h_die(2, "--bits (2048|3072|4096) é obrigatório");
    if (strcmp(a.mode, "version") && strcmp(a.mode, "keygen") && !a.keydir) h_die(2, "--keydir é obrigatório");
    if (a.keygen_rounds < 0) h_die(2, "--keygen-rounds negativo");
    return a;
}

/* Lê um arquivo inteiro; *len recebe o tamanho. Acrescenta um '\0' (não contado). */
static inline unsigned char *h_read(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "erro: abrir %s: %s\n", path, strerror(errno)); fflush(stderr); _exit(5); }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char *b = (unsigned char *)malloc((size_t)n + 1);
    if (!b || fread(b, 1, (size_t)n, f) != (size_t)n) h_die(5, "leitura de arquivo");
    b[n] = 0;
    fclose(f);
    *len = (size_t)n;
    return b;
}

static inline void h_keypath(char *out, size_t sz, const h_args *a, const char *file) {
    snprintf(out, sz, "%s/%d/%s", a->keydir, a->bits, file);
}

static inline void h_print_hex(const unsigned char *b, size_t n) {
    for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
    printf("\n");
}

static inline unsigned char *h_unhex(const unsigned char *s, size_t slen, size_t *out_len) {
    while (slen && (s[slen - 1] == '\n' || s[slen - 1] == '\r' || s[slen - 1] == ' ')) slen--;
    if (slen % 2) h_die(2, "hex de tamanho ímpar");
    unsigned char *b = (unsigned char *)malloc(slen / 2 + 1);
    for (size_t i = 0; i < slen / 2; i++) {
        unsigned int v;
        if (sscanf((const char *)s + 2 * i, "%2x", &v) != 1) h_die(2, "hex inválido");
        b[i] = (unsigned char)v;
    }
    *out_len = slen / 2;
    return b;
}

/* Lista "10,100,1000" -> vetor; devolve a quantidade. */
static inline int h_sets(const char *s, long *out, int max) {
    int n = 0;
    const char *p = s;
    while (p && *p && n < max) {
        char *end;
        long v = strtol(p, &end, 10);
        if (end == p || v < 1) h_die(2, "--sets inválido");
        out[n++] = v;
        p = (*end == ',') ? end + 1 : end;
        if (*end && *end != ',') h_die(2, "--sets inválido");
    }
    if (n == 0) h_die(2, "--sets vazio");
    return n;
}

static inline void h_print_set(long iters, const char *op, const double *t, long n) {
    double sum = 0, mn = t[0], mx = t[0];
    for (long i = 0; i < n; i++) { sum += t[i]; if (t[i] < mn) mn = t[i]; if (t[i] > mx) mx = t[i]; }
    double mean = sum / (double)n, ss = 0;
    for (long i = 0; i < n; i++) ss += (t[i] - mean) * (t[i] - mean);
    printf("set,%ld,%s,%ld,%.9e,%.9e,%.9e,%.9e,%.9e\n", iters, op, n, mean, sqrt(ss / (double)n), mn, mx, sum);
    fflush(stdout);
}

static inline void h_wait_stdin(void) {
    char line[64];
    if (!fgets(line, sizeof line, stdin)) { /* EOF também encerra */ }
}

/* Operações que cada biblioteca fornece. enc/dec devolvem 0 em sucesso e alocam *out com malloc. */
typedef struct {
    const char *(*meta)(const h_args *a);           /* JSON com library, library_version, language, padding... */
    void (*load)(const h_args *a);                  /* carrega as chaves pré-geradas de a->keydir/a->bits */
    int (*enc)(const unsigned char *m, size_t mlen, unsigned char **out, size_t *olen);
    int (*dec)(const unsigned char *c, size_t clen, unsigned char **out, size_t *olen);
    void (*keygen)(int bits);                       /* gera uma chave de `bits` bits (só isto é cronometrado) */
    void (*keyinfo)(unsigned long *e, int *nbits);  /* fora do cronômetro: expoente e tamanho da chave gerada; libera-a */
} h_ops;

/* Geração de chaves: cronometra SÓ a chamada de geração da biblioteca; inspeciona a chave gerada depois. */
static inline void h_keygen_rounds(const h_args *a, const h_ops *ops) {
    for (int r = 1; r <= a->keygen_rounds; r++) {
        unsigned long e = 0;
        int nbits = 0;
        double t0 = h_now();
        ops->keygen(a->bits);
        double t1 = h_now();
        ops->keyinfo(&e, &nbits);
        printf("keygen,%d,%d,%.9e,%lu,%d\n", a->bits, r, t1 - t0, e, nbits);
        fflush(stdout);
    }
}

static inline int h_main(int argc, char **argv, const h_ops *ops) {
    h_args a = h_parse(argc, argv);
    if (!strcmp(a.mode, "version")) { printf("%s\n", ops->meta(&a)); return 0; }
    if (!strcmp(a.mode, "keygen")) {                 /* experimento independente de geração de chaves */
        printf("meta,%s\n", ops->meta(&a));
        fflush(stdout);
        h_keygen_rounds(&a, ops);
        printf("done\n");
        fflush(stdout);
        return 0;
    }
    if (!strcmp(a.mode, "decrypt")) {
        if (!a.in) h_die(2, "--in obrigatório");
        size_t hl, cl, pl;
        unsigned char *hx = h_read(a.in, &hl), *c = h_unhex(hx, hl, &cl), *p = NULL;
        ops->load(&a);
        if (ops->dec(c, cl, &p, &pl)) h_die(4, "decifração falhou");
        h_print_hex(p, pl);
        return 0;
    }
    if (!a.msg) h_die(2, "--msg obrigatório");
    size_t ml;
    unsigned char *m = h_read(a.msg, &ml);
    if (!strcmp(a.mode, "encrypt")) {
        unsigned char *c = NULL;
        size_t cl;
        ops->load(&a);
        if (ops->enc(m, ml, &c, &cl)) h_die(3, "cifração falhou (mensagem longa demais para o preenchimento?)");
        h_print_hex(c, cl);
        return 0;
    }
    if (!strcmp(a.mode, "hold")) {
        unsigned char *c = NULL, *p = NULL;
        size_t cl, pl;
        ops->load(&a);
        if (ops->enc(m, ml, &c, &cl) || ops->dec(c, cl, &p, &pl)) h_die(4, "cifração/decifração falhou");
        printf("READY ");
        h_print_hex(p, pl);
        fflush(stdout);
        h_wait_stdin();
        return 0;
    }
    if (strcmp(a.mode, "bench")) h_die(2, "modo desconhecido");
    if (!a.sets) h_die(2, "--sets obrigatório");
    long sets[16];
    int ns = h_sets(a.sets, sets, 16);
    printf("meta,%s\n", ops->meta(&a));
    fflush(stdout);
    h_keygen_rounds(&a, ops);
    ops->load(&a);                                    /* chaves pré-geradas (fora do cronômetro) */
    for (int s = 0; s < ns; s++) {
        long n = sets[s];
        double *te = (double *)malloc(sizeof(double) * (size_t)n), *td = (double *)malloc(sizeof(double) * (size_t)n);
        for (long i = 0; i < n; i++) {
            unsigned char *c = NULL, *p = NULL;
            size_t cl = 0, pl = 0;
            double t0 = h_now();
            int e1 = ops->enc(m, ml, &c, &cl);
            double t1 = h_now();
            int e2 = e1 ? 1 : ops->dec(c, cl, &p, &pl);
            double t2 = h_now();
            if (e1 || e2 || pl != ml || memcmp(p, m, ml)) h_die(4, "verificação falhou: decifrado != mensagem");
            te[i] = t1 - t0;
            td[i] = t2 - t1;
            free(c);
            free(p);
        }
        h_print_set(n, "encrypt", te, n);
        h_print_set(n, "decrypt", td, n);
        free(te);
        free(td);
    }
    printf("done\n");
    fflush(stdout);
    return 0;
}

#endif
