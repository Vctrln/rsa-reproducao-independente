# Reimplementação independente do protocolo de Rosa, Campiolo e Batista (SBSeg 2025). Ver README.md.
PY     := .venv/bin/python
PAPER  := paper_repro

.PHONY: help setup deps build test verify smoke full memory
help:
	@echo "make setup    cria .venv e instala requirements.txt (cryptography compilada contra o OpenSSL do sistema)"
	@echo "make deps     baixa Node.js 20.19.0, node-forge 1.3.1, Bouncy Castle 1.79 e PyCryptodome 3.21.0 (com verificação)"
	@echo "make build    compila as 12 implementações"
	@echo "make verify   confere a integridade dos dados distribuídos e recalcula a análise a partir dos dados brutos"
	@echo "make test     testes das implementações e da análise de memória (exige build, deps e gcore)"
	@echo "make smoke    coleta rápida preliminar (2048 bits, 1 execução) + análise"
	@echo "make full     coleta completa do protocolo (várias horas) + análise"
	@echo "make memory   capturas de memória das 12 implementações (exige gcore e permissão de ptrace)"

setup:
	python3 -m venv .venv
	$(PY) -m pip install -q --upgrade pip
	$(PY) -m pip install -q --no-binary cryptography -r requirements.txt

deps:
	$(MAKE) -C $(PAPER) deps

build:
	$(MAKE) -C $(PAPER) build

verify:
	$(PY) $(PAPER)/scripts/verificar_publico.py

test: build
	$(PY) -m pytest -q $(PAPER)/tests

smoke: build
	$(PY) $(PAPER)/scripts/run_paper.py --profile smoke
	$(PY) $(PAPER)/scripts/analisar_coleta.py --ultima preliminary

full: build
	$(PY) $(PAPER)/scripts/run_paper.py --profile full
	$(PY) $(PAPER)/scripts/analisar_coleta.py --ultima performance

memory: build
	$(PY) $(PAPER)/scripts/memory_paper.py
