# Reimplementação independente do protocolo de Rosa, Campiolo e Batista (SBSeg 2025).
# Chamado pelo Makefile da raiz (make deps|build|test|smoke) ou diretamente: make -C paper_repro <alvo>
#
# Flags de compilação C/C++: as dos makefiles dos autores (commit 1b3ffe0), SEM otimização explícita (-O0 padrão do
# GCC). O trabalho criptográfico ocorre nas bibliotecas compartilhadas (compiladas otimizadas pela distribuição);
# só o código de chamada usa estas flags. _POSIX_C_SOURCE é necessário para clock_gettime com -std=c11.
ROOT    := ..
PY      ?= $(ROOT)/.venv/bin/python
NODE    := vendor/node-v20.19.0-linux-x64/bin/node
BCJAR   := vendor/bcprov-jdk18on-1.79.jar
HDR     := implementations/common/harness.h

.PHONY: deps build test clean-build
build: build/c_openssl build/c_libgcrypt build/cpp_botan build/cpp_cryptopp build/java/.stamp build/rust/.stamp build/rusage_exec

deps:
	tools/fetch_deps.sh

build/rusage_exec: tools/rusage_exec.c
	@mkdir -p build
	gcc -O2 -Wall -Wextra -o $@ $<

build/c_openssl: implementations/c_openssl/bench.c $(HDR)
	@mkdir -p build
	gcc -Wall -Wextra -o $@ $< -lcrypto -lm

build/c_libgcrypt: implementations/c_libgcrypt/bench.c $(HDR)
	@mkdir -p build
	gcc -Wall -Wextra -std=c11 -D_POSIX_C_SOURCE=200809L -o $@ $< -lgcrypt -lm

build/cpp_botan: implementations/cpp_botan/bench.cpp $(HDR)
	@mkdir -p build
	g++ -std=c++20 $(shell pkg-config --cflags botan-2) -o $@ $< $(shell pkg-config --libs botan-2)

build/cpp_cryptopp: implementations/cpp_cryptopp/bench.cpp $(HDR)
	@mkdir -p build
	g++ -std=c++11 -Wall $(shell pkg-config --cflags libcrypto++) -o $@ $< $(shell pkg-config --libs libcrypto++)

build/java/.stamp: $(wildcard implementations/java/src/paper/*.java) $(BCJAR)
	@mkdir -p build/java
	javac -encoding UTF-8 -d build/java -cp $(BCJAR) implementations/java/src/paper/*.java
	@touch $@

build/rust/.stamp: implementations/rust/Cargo.toml implementations/rust/Cargo.lock $(wildcard implementations/rust/src/*.rs implementations/rust/src/bin/*.rs)
	cd implementations/rust && cargo build --release --locked --target-dir ../../build/rust
	@touch $@

$(BCJAR) $(NODE):
	tools/fetch_deps.sh

test: build
	cd $(ROOT) && $(PY) -m pytest -q paper_repro/tests

clean-build:
	rm -rf build
