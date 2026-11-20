# Contrato comum das 12 implementações

Toda implementação, seja C, C++, Java, JavaScript, Python ou Rust, é um programa de linha de comando com a mesma
interface e a mesma saída. O orquestrador (`scripts/run_paper.py`) não conhece detalhes de nenhuma biblioteca: o
comando de cada uma está em `scripts/paper_common.py::impl_argv`.

```
<prog> version
<prog> bench   --keydir D --bits B --msg M --sets 10,100,1000,10000 --keygen-rounds R [--padding P]
<prog> keygen  --bits B --keygen-rounds R                     # experimento independente de geração de chaves
<prog> encrypt --keydir D --bits B --msg M [--padding P]       # stdout: texto cifrado em hex
<prog> decrypt --keydir D --bits B --in ARQ_HEX [--padding P]  # stdout: texto decifrado em hex
<prog> hold    --keydir D --bits B --msg M [--padding P]       # carrega as chaves, cifra e decifra 1 vez,
                                                               # imprime "READY <hex>" e espera uma linha no stdin
```

- **`--keydir D --bits B`:** as chaves ficam em `D/B/`, nos arquivos `private.pem` e `public.pem` (PKCS#8/SPKI),
  `private.der` e `public.der` (Crypto++) e `private.sexp` e `public.sexp` (Libgcrypt). São gerados por
  `tools/keys.py`.
- **`--padding`:** o padrão de cada programa é o preenchimento definido em `protocol/protocol.toml`. Um valor
  diferente é recusado com saída 2. A exceção é o Libgcrypt, que aceita `raw` para a variante suplementar.
- **Códigos de saída:**

  | Código | Significado |
  |---|---|
  | 0 | ok |
  | 2 | argumento inválido |
  | 3 | cifração recusada (mensagem acima do limite do preenchimento) |
  | 4 | decifração falhou ou verificação divergiu |
  | 5 | erro de E/S, chave ou biblioteca |

## Saída de `bench` (uma linha por registro)

```
meta,<json: id, language, library, library_version, runtime, padding, ...>
keygen,<bits>,<rodada>,<segundos>,<expoente público gerado>,<bits do módulo gerado>
set,<N>,encrypt,<n>,<média_s>,<dp_pop_s>,<mín_s>,<máx_s>,<total_s>
set,<N>,decrypt,<n>,<média_s>,<dp_pop_s>,<mín_s>,<máx_s>,<total_s>
...
done
```

## Laço medido (idêntico nas 12)

1. **Geração de chave:** `R` gerações com a função de geração da própria biblioteca. Só a chamada de geração é
   cronometrada; depois, fora do cronômetro, o programa informa o expoente público e o tamanho do módulo da chave
   gerada, e a coleta confere esses valores. No protocolo, a geração é um **experimento independente** (modo
   `keygen`, unidades `kg_*`), e as unidades de cifração/decifração (`ed_*`) usam `--keygen-rounds 0`.
2. **Carga das chaves pré-geradas:** feita fora do cronômetro.
3. **Conjuntos de N iterações,** na ordem dada. Em cada iteração:
   - cronometra-se a cifração da mensagem;
   - cronometra-se a decifração desse texto cifrado;
   - fora do cronômetro, confere-se que o decifrado é igual à mensagem. Se não for, o programa sai com código 4.
4. **Estatística por conjunto:** média e desvio padrão populacional das N medidas, como em
   `calcular_desvio_padrao()` do código C dos autores.

**Relógio:** é monotônico em todas as linguagens:

| Linguagem | Relógio |
|---|---|
| C e C++ | `clock_gettime(CLOCK_MONOTONIC)` |
| Java | `System.nanoTime` |
| JavaScript | `process.hrtime.bigint` |
| Python | `time.perf_counter_ns` |
| Rust | `Instant` |

**Padrão de chamada:** o que fica dentro do cronômetro reproduz o padrão do código dos autores. Por exemplo:

- OpenSSL C e Java Crypto: um contexto ou `Cipher` novo por operação;
- Crypto++: um RNG e um encryptor novos por operação;
- Node `crypto`: o PEM é interpretado a cada chamada;
- Bouncy Castle: conversão para hex;
- Botan e PyCryptodome: objetos criados uma única vez.

Os comentários no início de cada fonte dizem o que foi conferido no código dos autores (commit `1b3ffe0`).
