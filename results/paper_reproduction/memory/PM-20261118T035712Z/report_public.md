# Análise de memória — PM-20261118T035712Z

Método v3 · gcore: /usr/bin/gcore · ptrace_scope: sem Yama (kernel WSL) · chave de 2048 bits · 3 captura(s) por biblioteca · blocos de 16 B (mín. 6 bytes distintos; trechos estruturais comuns às duas chaves excluídos).

**Métodos.** A = linhas PEM (`strings | grep`); B = arquivo de chave carregado pela biblioteca (blocos de 64 B); C = DER PKCS#8 inteiro / blocos de 16 B normais + invertidos (§3.3), maior sequência de blocos consecutivos em offsets consecutivos (normal/invertida) e contagem com blocos de 8 B (§4.3); D = componentes secretos d, p, q, dp, dq, qinv inteiros, nos layouts be (big-endian), le (little-endian), java (int[]) e cpython (dígitos de 30 bits); E = o que o script publicado pelos autores efetivamente busca (chave PÚBLICA; inteira ou nº de blocos); Recuperação = às cegas, sem usar a chave conhecida: por estrutura (DER 30 82 … 02 01 00 / PEM BEGIN) ou por fator de n em janelas alinhadas; só conta se a chave reconstruída decifrar um texto de teste. Controle = nº de acertos de uma chave que nunca foi carregada (tem de ser 0).

| Biblioteca | Rep. | Dump (MB) | A PEM | B arquivo | C DER (inteiro / blocos) | D componentes inteiros | E pública | Controle | Recuperação | Classificação |
|---|---|---|---|---|---|---|---|---|---|---|
| c_openssl | 1 | 2 | 0/26 | 0/26 | não / 6+65inv de 76; contíguos 6/15inv; 8 B: 25+137inv de 150 | d(le), p(le), q(le), dp(le), dq(le), qinv(le) | 0 | 0 | sim: fator alinhado | chave recuperada sem conhecimento prévio |
| c_libgcrypt | 1 | 1 | 0/26 | 20/29 | não / 51+6inv de 76; contíguos 15/6inv; 8 B: 107+13inv de 150 | d(be), p(be), q(be), qinv(be) | 16 | 0 | sim: fator alinhado | chave recuperada sem conhecimento prévio |
| cpp_botan | 1 | 207 | 14/26 | 15/26 | não / 15+15inv de 76; contíguos 15/15inv; 8 B: 32+31inv de 150 | nenhum | 15 | 0 | não | fragmentos encontrados |
| cpp_cryptopp | 1 | 3 | 0/26 | 18/19 | não / 74+65inv de 76; contíguos 74/15inv; 8 B: 148+137inv de 150 | d(be/le), p(be/le), q(be/le), dp(be/le), dq(be/le), qinv(be/le) | 16 | 0 | sim: fator alinhado | chave recuperada sem conhecimento prévio |
| java_bouncycastle | 1 | 5230 | 26/26 | 26/26 | sim / 76+15inv de 76; contíguos 76/15inv; 8 B: 150+31inv de 150 | d(be/java), p(be/java), q(be/java), dp(be/java), dq(be/java), qinv(be/java) | inteira | 0 | sim: estrutura DER/PEM | chave recuperada sem conhecimento prévio |
| java_jca | 1 | 4958 | 26/26 | 26/26 | sim / 76+0inv de 76; contíguos 76/0inv; 8 B: 150+0inv de 150 | d(be/java), p(be/java), q(be/java), dp(be/java), dq(be/java), qinv(be/java) | inteira | 0 | sim: estrutura DER/PEM | chave recuperada sem conhecimento prévio |
| js_crypto | 1 | 661 | 26/26 | 26/26 | não / 15+3inv de 76; contíguos 15/3inv; 8 B: 33+7inv de 150 | nenhum | 15 | 0 | sim: estrutura DER/PEM | chave recuperada sem conhecimento prévio |
| js_forge | 1 | 935 | 26/26 | 26/26 | sim / 76+0inv de 76; contíguos 76/0inv; 8 B: 150+0inv de 150 | d(be), p(be), q(be), dp(be), dq(be), qinv(be) | inteira | 0 | sim: estrutura DER/PEM | chave recuperada sem conhecimento prévio |
| py_cryptography | 1 | 14 | 0/26 | 0/26 | não / 12+65inv de 76; contíguos 11/15inv; 8 B: 30+137inv de 150 | d(le), p(le), q(le), dp(le), dq(le), qinv(le) | 12 | 0 | sim: fator alinhado | chave recuperada sem conhecimento prévio |
| py_pycryptodome | 1 | 14 | 14/26 | 0/26 | não / 39+58inv de 76; contíguos 23/15inv; 8 B: 86+122inv de 150 | d(le), p(le), q(le), dp(be/le), dq(be/le) | 0 | 0 | sim: fator alinhado | chave recuperada sem conhecimento prévio |
| rust_openssl | 1 | 2 | 0/26 | 0/26 | não / 0+65inv de 76; contíguos 0/15inv; 8 B: 9+137inv de 150 | d(le), p(le), q(le), dp(le), dq(le), qinv(le) | 0 | 0 | sim: fator alinhado | chave recuperada sem conhecimento prévio |
| rust_rustcrypto | 1 | 1 | 0/26 | 0/26 | não / 15+65inv de 76; contíguos 15/15inv; 8 B: 32+137inv de 150 | d(le), p(le), q(le), dp(le), dq(le), qinv(le) | 17 | 0 | sim: fator alinhado | chave recuperada sem conhecimento prévio |
| c_libgcrypt | 2 | 1 | 0/26 | 20/29 | não / 52+6inv de 76; contíguos 15/6inv; 8 B: 108+13inv de 150 | d(be), p(be), q(be), qinv(be) | 16 | 0 | sim: fator alinhado | chave recuperada sem conhecimento prévio |
| cpp_botan | 2 | 207 | 14/26 | 15/26 | não / 16+15inv de 76; contíguos 15/15inv; 8 B: 33+31inv de 150 | nenhum | 15 | 0 | não | fragmentos encontrados |
| cpp_cryptopp | 2 | 3 | 0/26 | 1/19 | não / 6+66inv de 76; contíguos 6/15inv; 8 B: 13+138inv de 150 | d(le), p(le), q(le), dp(le), dq(le), qinv(le) | 6 | 0 | sim: fator alinhado | chave recuperada sem conhecimento prévio |
| java_bouncycastle | 2 | 5298 | 26/26 | 26/26 | sim / 76+15inv de 76; contíguos 76/15inv; 8 B: 150+31inv de 150 | d(be/java), p(be/java), q(be/java), dp(be/java), dq(be/java), qinv(be/java) | inteira | 0 | sim: estrutura DER/PEM | chave recuperada sem conhecimento prévio |
| java_jca | 2 | 4958 | 26/26 | 26/26 | sim / 76+0inv de 76; contíguos 76/0inv; 8 B: 150+0inv de 150 | d(be/java), p(be/java), q(be/java), dp(be/java), dq(be/java), qinv(be/java) | inteira | 0 | sim: estrutura DER/PEM | chave recuperada sem conhecimento prévio |
| js_crypto | 2 | 661 | 26/26 | 26/26 | não / 15+3inv de 76; contíguos 15/3inv; 8 B: 33+7inv de 150 | nenhum | 15 | 0 | sim: estrutura DER/PEM | chave recuperada sem conhecimento prévio |
| js_forge | 2 | 935 | 26/26 | 26/26 | sim / 76+0inv de 76; contíguos 76/0inv; 8 B: 150+0inv de 150 | d(be), p(be), q(be), dp(be), dq(be), qinv(be) | inteira | 0 | sim: estrutura DER/PEM | chave recuperada sem conhecimento prévio |
| py_cryptography | 2 | 14 | 0/26 | 0/26 | não / 12+66inv de 76; contíguos 11/15inv; 8 B: 30+138inv de 150 | d(le), p(le), q(le), dp(le), dq(le), qinv(le) | 12 | 0 | sim: fator alinhado | chave recuperada sem conhecimento prévio |
| py_pycryptodome | 2 | 14 | 14/26 | 0/26 | não / 39+58inv de 76; contíguos 23/15inv; 8 B: 86+122inv de 150 | d(le), p(le), q(le), dp(be/le), dq(be/le) | 0 | 0 | sim: fator alinhado | chave recuperada sem conhecimento prévio |
| rust_openssl | 2 | 2 | 0/26 | 0/26 | não / 0+65inv de 76; contíguos 0/15inv; 8 B: 10+137inv de 150 | d(le), p(le), q(le), dp(le), dq(le), qinv(le) | 0 | 0 | sim: fator alinhado | chave recuperada sem conhecimento prévio |
| rust_rustcrypto | 2 | 1 | 0/26 | 0/26 | não / 15+66inv de 76; contíguos 15/15inv; 8 B: 32+138inv de 150 | d(le), p(le), q(le), dp(le), dq(le), qinv(le) | 17 | 0 | sim: fator alinhado | chave recuperada sem conhecimento prévio |
| c_openssl | 2 | 2 | 0/26 | 0/26 | não / 6+66inv de 76; contíguos 6/15inv; 8 B: 25+138inv de 150 | d(le), p(le), q(le), dp(le), dq(le), qinv(le) | 0 | 0 | sim: fator alinhado | chave recuperada sem conhecimento prévio |
| cpp_botan | 3 | 207 | 14/26 | 15/26 | não / 15+15inv de 76; contíguos 15/15inv; 8 B: 32+31inv de 150 | nenhum | 15 | 0 | não | fragmentos encontrados |
| cpp_cryptopp | 3 | 3 | 0/26 | 18/19 | não / 74+65inv de 76; contíguos 74/15inv; 8 B: 148+137inv de 150 | d(be/le), p(be/le), q(be/le), dp(be/le), dq(be/le), qinv(be/le) | 16 | 0 | sim: fator alinhado | chave recuperada sem conhecimento prévio |
| java_bouncycastle | 3 | 5298 | 26/26 | 26/26 | sim / 76+15inv de 76; contíguos 76/15inv; 8 B: 150+31inv de 150 | d(be/java), p(be/java), q(be/java), dp(be/java), dq(be/java), qinv(be/java) | inteira | 0 | sim: estrutura DER/PEM | chave recuperada sem conhecimento prévio |
| java_jca | 3 | 4958 | 26/26 | 26/26 | sim / 76+0inv de 76; contíguos 76/0inv; 8 B: 150+0inv de 150 | d(be/java), p(be/java), q(be/java), dp(be/java), dq(be/java), qinv(be/java) | inteira | 0 | sim: estrutura DER/PEM | chave recuperada sem conhecimento prévio |
| js_crypto | 3 | 661 | 26/26 | 26/26 | não / 15+3inv de 76; contíguos 15/3inv; 8 B: 33+7inv de 150 | nenhum | 15 | 0 | sim: estrutura DER/PEM | chave recuperada sem conhecimento prévio |
| js_forge | 3 | 935 | 26/26 | 26/26 | sim / 76+0inv de 76; contíguos 76/0inv; 8 B: 150+0inv de 150 | d(be), p(be), q(be), dp(be), dq(be), qinv(be) | inteira | 0 | sim: estrutura DER/PEM | chave recuperada sem conhecimento prévio |
| py_cryptography | 3 | 14 | 0/26 | 0/26 | não / 12+65inv de 76; contíguos 11/15inv; 8 B: 30+137inv de 150 | d(le), p(le), q(le), dp(le), dq(le), qinv(le) | 12 | 0 | sim: fator alinhado | chave recuperada sem conhecimento prévio |
| py_pycryptodome | 3 | 14 | 14/26 | 0/26 | não / 39+58inv de 76; contíguos 23/15inv; 8 B: 86+122inv de 150 | d(le), p(le), q(le), dp(be/le), dq(be/le) | 0 | 0 | sim: fator alinhado | chave recuperada sem conhecimento prévio |
| rust_openssl | 3 | 2 | 0/26 | 0/26 | não / 0+65inv de 76; contíguos 0/15inv; 8 B: 9+137inv de 150 | d(le), p(le), q(le), dp(le), dq(le), qinv(le) | 0 | 0 | sim: fator alinhado | chave recuperada sem conhecimento prévio |
| rust_rustcrypto | 3 | 1 | 0/26 | 0/26 | não / 15+65inv de 76; contíguos 15/15inv; 8 B: 32+137inv de 150 | d(le), p(le), q(le), dp(le), dq(le), qinv(le) | 17 | 0 | sim: fator alinhado | chave recuperada sem conhecimento prévio |
| c_openssl | 3 | 2 | 0/26 | 0/26 | não / 6+65inv de 76; contíguos 6/15inv; 8 B: 25+137inv de 150 | d(le), p(le), q(le), dp(le), dq(le), qinv(le) | 0 | 0 | sim: fator alinhado | chave recuperada sem conhecimento prévio |
| c_libgcrypt | 3 | 1 | 0/26 | 20/29 | não / 51+6inv de 76; contíguos 15/6inv; 8 B: 107+13inv de 150 | d(be), p(be), q(be), qinv(be) | 16 | 0 | sim: fator alinhado | chave recuperada sem conhecimento prévio |

## Resumo por biblioteca (todas as repetições)

| Biblioteca | Capturas | Recuperada às cegas | Material secreto completo | Classificações |
|---|---|---|---|---|
| c_openssl | 3 | 3/3 (fator alinhado) | 3/3 | chave recuperada sem conhecimento prévio |
| c_libgcrypt | 3 | 3/3 (fator alinhado) | 3/3 | chave recuperada sem conhecimento prévio |
| cpp_botan | 3 | 0/3 (—) | 0/3 | fragmentos encontrados |
| cpp_cryptopp | 3 | 3/3 (fator alinhado) | 3/3 | chave recuperada sem conhecimento prévio |
| java_bouncycastle | 3 | 3/3 (estrutura DER/PEM) | 3/3 | chave recuperada sem conhecimento prévio |
| java_jca | 3 | 3/3 (estrutura DER/PEM) | 3/3 | chave recuperada sem conhecimento prévio |
| js_crypto | 3 | 3/3 (estrutura DER/PEM) | 3/3 | chave recuperada sem conhecimento prévio |
| js_forge | 3 | 3/3 (estrutura DER/PEM) | 3/3 | chave recuperada sem conhecimento prévio |
| py_cryptography | 3 | 3/3 (fator alinhado) | 3/3 | chave recuperada sem conhecimento prévio |
| py_pycryptodome | 3 | 3/3 (fator alinhado) | 3/3 | chave recuperada sem conhecimento prévio |
| rust_openssl | 3 | 3/3 (fator alinhado) | 3/3 | chave recuperada sem conhecimento prévio |
| rust_rustcrypto | 3 | 3/3 (fator alinhado) | 3/3 | chave recuperada sem conhecimento prévio |

## Limites

- "Não encontrado" significa só "não encontrado por este método" (ex.: inteiros do CPython e do forge usam dígitos de 30/28 bits, que não aparecem como sequência de bytes). "Encontrado" não prova vulnerabilidade explorável: o dump exige privilégio sobre o processo.
- O tamanho do dump do gcore NÃO é o consumo de RAM: o gcore grava as regiões mapeadas (bibliotecas, heap reservado, pilhas).
- Um instante de captura por processo, logo após uma cifração e uma decifração; o artigo não informa em que momento capturou nem quantas vezes.
- Coluna E: o script publicado busca a chave PÚBLICA (ver docstring de memory_paper.py); encontrá-la não expõe segredo algum. Está aqui só para mostrar o que aquele script mediria.
