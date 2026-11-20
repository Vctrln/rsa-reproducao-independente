# Desempenho e segurança de implementações RSA: reimplementação independente

Este repositório contém uma **reimplementação independente** dos experimentos descritos no artigo de Rosa,
Campiolo e Batista (SBSeg 2025). Tem o código escrito pela equipe, os dados brutos dos nossos experimentos e os
resultados obtidos com eles.

**Este não é o código dos autores originais.** O trabalho não é afiliado aos autores do estudo original nem
endossado por eles. Para consultar o trabalho original, use os links da seção "Estudo de referência".

**Autores da reimplementação:**

- Mateus Leitão Mendes
- Victor Emanuel Pereira de Sousa

Os dois são responsáveis pela implementação independente, pelos experimentos próprios e pelos resultados
disponibilizados aqui. Este repositório contém só materiais próprios da reimplementação e não redistribui código
ou bases de dados extraídos do trabalho original.

## Estudo de referência

> ROSA, A. C. Q.; CAMPIOLO, R.; BATISTA, D. M. Avaliação de desempenho e segurança de diferentes implementações
> do sistema de criptografia RSA. In: Workshop de Trabalhos de Iniciação Científica e de Graduação (WTICG),
> Simpósio Brasileiro de Cibersegurança (SBSeg), 25., 2025, Foz do Iguaçu/PR. *Anais Estendidos* [...].
> Porto Alegre: Sociedade Brasileira de Computação, 2025. p. 180–191. DOI: 10.5753/sbseg_estendido.2025.11863.

- Artigo (DOI): <https://doi.org/10.5753/sbseg_estendido.2025.11863>
- Página do artigo na SBC OpenLib: <https://sol.sbc.org.br/index.php/sbseg_estendido/article/view/36757>
- Repositório dos autores, indicado no artigo: <https://github.com/anacarlaquallio/tcc2>. Consultamos o commit
  `1b3ffe0138fde918f5bcba40a25cb107b387b61b` só para conferir parâmetros e padrões de chamada.

## Relação entre os dois trabalhos

O estudo original comparou 12 bibliotecas RSA em seis linguagens (C, C++, Java, JavaScript, Python e Rust) em
duas frentes:

- o tempo de geração de chaves, cifração e decifração;
- a presença da chave privada em despejos de memória dos processos.

A equipe executou o protocolo descrito no artigo com **implementações, ambiente, chaves e mensagem próprios**.

**O que a equipe escreveu:**

- as 12 implementações de medição (`paper_repro/implementations/`), cada uma sobre a biblioteca que o artigo
  avalia, e o *harness* comum de medição em cada linguagem;
- a geração e a conversão das chaves de laboratório (`paper_repro/tools/keys.py`);
- o executor das coletas (`run_paper.py`), com ordem rotativa das bibliotecas, fixação de núcleo, validação e
  gravação atômica de cada unidade;
- a análise de memória (`memory_paper.py`). Ela captura o processo com `gcore`, busca o material da chave em vários
  formatos e tenta **recuperar a chave sem conhecê-la previamente**. A recuperação só conta se a chave reconstruída
  decifrar um texto de teste. Uma chave de controle, que nunca é carregada, serve de controle negativo;
- a análise dos dados próprios (`analisar_coleta.py`), o verificador (`verificar_publico.py`) e os testes.

As implementações seguem os padrões de chamada descritos no artigo e observados no repositório dos autores, mas
foram escritas de forma independente. Nenhum arquivo do repositório dos autores foi copiado.

**O que este repositório não redistribui:**

- código-fonte dos autores originais;
- o PDF do artigo;
- figuras ou tabelas do artigo;
- valores extraídos das figuras ou das tabelas do artigo;
- bases de dados do estudo original.

Por isso, ele **não inclui a comparação numérica com os valores publicados**, que existe na versão acadêmica do
trabalho. Os dados e os resultados distribuídos aqui são **exclusivamente das nossas coletas**.

## Estrutura

```
paper_repro/
  implementations/   12 implementações (C, C++, Java, JavaScript, Python, Rust) e harness comum; CONTRACT.md
  protocol/          protocol.toml (parâmetros do protocolo) e message_90B.txt (mensagem de 90 B, própria)
  scripts/           run_paper.py (coleta de desempenho), memory_paper.py (análise de memória),
                     analisar_coleta.py (análise), verificar_publico.py (verificação), paper_common.py, paper_data.py
  tools/             keys.py (chaves), refcrypto.py (referência de interoperabilidade), integrity.py,
                     rusage_exec.c (RSS/CPU por processo), fetch_deps.sh (dependências fora do apt)
  tests/             testes das implementações e da análise de memória
results/paper_reproduction/
  performance/P-20261117T051242Z/   coleta definitiva de desempenho
  memory/PM-20261118T035712Z/       coleta de memória
  integrity/                        registros de integridade (SHA-256) gerados ao fim de cada coleta
PROCEDENCIA.csv     o que foi excluído ou alterado em relação aos registros originais das coletas, com SHA-256
SHA256SUMS          SHA-256 de todos os arquivos distribuídos
```

## Instalação

O ambiente usado foi Ubuntu 24.04 (WSL2), com GCC 13.3, OpenJDK 11, Rust 1.99, Python 3.12 e gdb 15.1. Em outros
ambientes, as versões das bibliotecas podem diferir.

```sh
# 1. Pacotes do sistema (uma vez)
sudo apt-get install -y build-essential pkg-config libssl-dev libgcrypt20-dev libbotan-2-dev libcrypto++-dev \
    openjdk-11-jdk-headless python3-venv python3-dev gdb curl xz-utils
# Rust (cargo e rustc) pelo rustup: https://rustup.rs

# 2. Ambiente Python (.venv); a cryptography é compilada contra o OpenSSL do sistema
make setup

# 3. Dependências fora do apt, com verificação de integridade (Node.js 20.19.0, node-forge 1.3.1,
#    Bouncy Castle 1.79, PyCryptodome 3.21.0), em paper_repro/vendor/
make deps

# 4. Compilação das 12 implementações (paper_repro/build/)
make build
```

## Execução

| Objetivo | Comando | Observação |
|---|---|---|
| Conferir os dados e os resultados distribuídos | `make verify` | Não exige compilação. Recalcula a análise a partir dos dados brutos |
| Testar as implementações e a análise de memória | `make test` | Exige `make deps` e `make build`; os testes de memória usam `gcore` |
| Coleta rápida de verificação | `make smoke` | 2048 bits, 1 execução, conjuntos de 10 e 20 operações; preliminar |
| Coleta completa do protocolo | `make full` | Várias horas. Gera uma pasta nova `performance/P-<UTC>/` |
| Análise de memória das 12 implementações | `make memory` | Exige `gcore` e permissão de `ptrace` sobre os processos |

A coleta fixa os processos no núcleo 1 com `taskset`. Para desativar, use
`.venv/bin/python paper_repro/scripts/run_paper.py --no-pin`; a coleta passa a ser marcada como preliminar.

Nenhuma coleta sobrescreve outra: cada execução cria uma pasta com data e hora em UTC.

Para analisar qualquer coleta:

```sh
.venv/bin/python paper_repro/scripts/analisar_coleta.py <pasta da coleta>
```

## Dados e resultados próprios

### Desempenho: `results/paper_reproduction/performance/P-20261117T051242Z/`

A coleta tem 375 unidades. Cada unidade é um processo:

- **Geração de chaves (180 unidades):** 12 bibliotecas × 3 tamanhos de chave (2048, 3072 e 4096 bits) ×
  5 execuções.
- **Cifração e decifração (195 unidades):** as mesmas combinações, mais a variante `c_libgcrypt_raw`. Cada unidade
  mede conjuntos de 10, 100, 1000 e 10000 operações. O conjunto de 10 é registrado, mas não entra nos agregados.

| Arquivo | Conteúdo |
|---|---|
| `raw/*.txt` | Saída de cada unidade (tempos por conjunto e gerações de chave) |
| `manifest.json` | Configuração, plano, ambiente, versões das bibliotecas, SHA-256 dos binários e das fontes, rusage por unidade |
| `keys/*/public.*`, `keys/keys.json` | Chaves públicas usadas e SHA-256 de todas as chaves; as privadas não são distribuídas |
| `message.txt` | Mensagem de 90 B usada |
| `analysis/measurements.csv` | Uma linha por (unidade, operação, conjunto) |
| `analysis/summary_sets.csv` | Média das 5 execuções por biblioteca, chave, operação e conjunto |
| `analysis/keygen.csv`, `analysis/summary_keygen.csv` | Gerações de chave e seu resumo (média, desvio, mediana, expoente) |
| `analysis/resources.csv`, `analysis/summary_resources.csv` | RSS máximo e tempo de CPU por processo |
| `figures/reproduction_*.png` | Tempo médio por biblioteca, por operação e tamanho de chave |

### Memória: `results/paper_reproduction/memory/PM-20261118T035712Z/`

A coleta tem 36 capturas: 12 bibliotecas × 3 repetições, com chave de 2048 bits.

| Arquivo | Conteúdo |
|---|---|
| `captures/*.json` | Registro de cada captura: buscas, controle negativo, recuperação e classificação |
| `memory_results.json` | Registro agregado da coleta, com ambiente e versões |
| `events.log` | Eventos da coleta |
| `report_public.md` | Relatório por captura e por biblioteca, gerado de `memory_results.json` |

Os despejos de memória foram sobrescritos e apagados ao fim de cada captura. Os registros guardam só contagens,
posições e classificações.

**Resultado:** a chave privada em uso foi recuperada sem conhecimento prévio e comprovada por decifração nas
3 repetições de 11 das 12 implementações. Não houve acerto no controle negativo. Na Botan, a chave não foi
recuperada.

Esses resultados valem para um adversário com privilégio de depuração sobre o processo, num único instante de
captura logo após uma cifração e uma decifração.

### Procedência e integridade

Os arquivos em `integrity/` são os registros originais, gerados ao fim de cada coleta e mantidos sem alteração.
Eles documentam a procedência das coletas: listam o nome e o SHA-256 de **todos** os arquivos que existiam em cada
pasta de coleta. Por isso, mencionam também arquivos que não fazem parte desta versão pública, como as chaves
privadas e as análises comparativas com o artigo original.

Esses registros contêm apenas nomes e hashes. **Não disponibilizam o conteúdo dos arquivos excluídos**, e não é
possível reconstruir esse conteúdo a partir do hash.

A versão pública não inclui alguns arquivos daquelas pastas e alterou outros. `PROCEDENCIA.csv` lista cada caso
com o SHA-256 original e o motivo, assim como os arquivos de código adaptados ou criados para esta versão:

- **Excluídos:** as chaves privadas e as análises e figuras que comparavam com valores do artigo original.
- **Alterados:**
  - em `manifest.json` e `keys/keys.json`, os caminhos locais foram substituídos por `<RAIZ_DO_PROJETO>` e os
    campos com conteúdo do artigo foram retirados;
  - em algumas fontes, só os comentários mudaram. Os parâmetros do protocolo continuam os mesmos (o `config_id`
    confere).

`make verify` confere tudo isso automaticamente.

## O que foi testado nesta versão

Os procedimentos abaixo foram executados numa cópia limpa desta versão, no ambiente descrito em "Instalação":

| Procedimento | Situação |
|---|---|
| `make setup`, `make deps`, `make build` | Executados com sucesso; as 12 implementações compilaram |
| `make verify` | Executado com sucesso: conferiu a integridade dos materiais distribuídos e recalculou os 6 CSV de `analysis/` a partir dos dados brutos, com resultado idêntico |
| `make test` | 280 testes aprovados, incluindo capturas reais com `gcore` em processos de teste |
| `make smoke` | Executado com sucesso: coleta preliminar rápida, validação e análise |
| `make full` | **Não executado nesta etapa**, porque repetiria os experimentos completos (várias horas) |
| `make memory` | **Não executado como coleta integral nesta etapa**. A captura foi exercitada só pelos testes automatizados |

Os testes automatizados e a coleta `smoke` verificam que o código funciona. **Eles não equivalem à repetição
integral dos experimentos.** Os resultados distribuídos vêm das coletas completas originais
(`P-20261117T051242Z` e `PM-20261118T035712Z`).

## Limitações de reprodução

- **Tempos absolutos:** dependem do hardware, do sistema e das versões das bibliotecas. Uma nova coleta não deve
  reproduzir os mesmos valores. Com as mesmas versões, deve reproduzir a mesma ordem de grandeza e,
  aproximadamente, a mesma ordem entre as bibliotecas.
- **Chaves privadas:** não são distribuídas. Por isso:
  - não é possível repetir cifração e decifração com as mesmas chaves;
  - `make full` e `make memory` geram chaves novas;
  - a análise e a verificação dos dados distribuídos conferem só as chaves públicas.
- **Ambiente da coleta:** foi WSL2. A captura de memória exige `gcore` e permissão de `ptrace`; em sistemas com Yama
  (`ptrace_scope` ≥ 1), pode ser preciso ajustar a permissão ou executar com privilégio.
- **Versões:** a Botan usada é a 2.19.3, do apt do Ubuntu 24.04.
- **Fontes alteradas só em comentários:** treze arquivos de fonte (onze das implementações e dos *harnesses*,
  `Cargo.toml` e `protocol.toml`) diferem dos usados na coleta apenas nos comentários. O SHA-256 das versões usadas está no
  `manifest.json` e em `PROCEDENCIA.csv`.
- **Scripts adaptados para esta versão:**
  - `run_paper.py` não estima mais a duração da coleta, porque a estimativa usava os tempos publicados no artigo;
  - `memory_paper.py` não gera mais a coluna de comparação com o artigo;
  - `analisar_coleta.py` reúne a parte da análise acadêmica que trata só dos dados próprios.

## Licenças

| Material | Licença |
|---|---|
| Código da equipe: `paper_repro/` (incluindo `protocol/` e `tests/`), `Makefile`, `requirements.txt`, `.gitignore` | MIT ([LICENSE](LICENSE)) |
| Dados e resultados próprios: `results/`, além de `README.md`, `PROCEDENCIA.csv` e `SHA256SUMS` | CC BY 4.0 ([LICENSE-DATA](LICENSE-DATA)) |
| Estudo original (artigo, código, figuras e tabelas) | Não incluído. Apenas citado; não está coberto por estas licenças |
| Dependências baixadas por `make deps` ou instaladas pelo `apt`, pelo `pip` e pelo `cargo` | Licenças próprias de cada projeto; não são redistribuídas aqui |

Titulares dos direitos sobre o código e os dados próprios: Mateus Leitão Mendes e Victor Emanuel Pereira de Sousa.

Qualquer pessoa pode reutilizar esses materiais nas condições das respectivas licenças, sem pedir autorização
prévia. As condições principais são manter o aviso de copyright e de licença (MIT) e dar a atribuição de autoria
(CC BY 4.0).

Atribuição sugerida para os dados e resultados: *Mateus Leitão Mendes e Victor Emanuel Pereira de Sousa (2026).
Dados e resultados próprios da reimplementação independente de Rosa, Campiolo e Batista (SBSeg 2025). CC BY 4.0*,
com o endereço do repositório em que o material foi obtido.
