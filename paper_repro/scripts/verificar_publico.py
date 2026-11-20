"""Verificação da versão pública: integridade dos arquivos, procedência dos dados e recálculo da análise.

Uso (da raiz do repositório):  python paper_repro/scripts/verificar_publico.py      (ou: make verify)

Confere:
  1. SHA256SUMS: todo arquivo listado existe e tem o SHA-256 registrado;
  2. registros de integridade originais (results/paper_reproduction/integrity/*.sha256): cada arquivo da coleta está
     presente e idêntico, ou está declarado em PROCEDENCIA.csv como excluído/alterado com o SHA-256 original certo;
  3. fontes usadas na coleta (manifest.json, sources_sha256): idênticas ou declaradas em PROCEDENCIA.csv;
  4. análise: recalcula, a partir dos dados brutos, os 6 CSV de analysis/ e confere byte a byte;
  5. memória: regenera o relatório a partir de memory_results.json e confere com report_public.md;
  6. ausência de chaves privadas e de arquivos do artigo original.
Saída 0 = tudo conferido; 1 = alguma falha.
"""
from __future__ import annotations

import csv
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
P = "results/paper_reproduction/performance/P-20261117T051242Z"
M = "results/paper_reproduction/memory/PM-20261118T035712Z"
falhas: list[str] = []


def sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def check(ok: bool, msg: str) -> None:
    print(f"  {'OK   ' if ok else 'FALHA'} {msg}")
    if not ok:
        falhas.append(msg)


def main() -> int:
    proc = {r["arquivo"]: r for r in csv.DictReader(open(ROOT / "PROCEDENCIA.csv", encoding="utf-8"))}

    print("1. SHA256SUMS")
    linhas = (ROOT / "SHA256SUMS").read_text().splitlines()
    ruins = [f for h, f in (l.split("  ", 1) for l in linhas) if not (ROOT / f).is_file() or sha(ROOT / f) != h]
    check(not ruins, f"{len(linhas)} arquivos listados; divergentes ou ausentes: {len(ruins)} {ruins[:3]}")

    print("2. Registros de integridade originais das coletas")
    for rec in sorted((ROOT / "results/paper_reproduction/integrity").glob("*.sha256")):
        iguais, decl, erro = 0, 0, []
        for l in rec.read_text().splitlines():
            h, f = l.split("  ", 1)
            p = ROOT / f
            if p.is_file() and sha(p) == h:
                iguais += 1
            elif f in proc and proc[f]["sha256_original"] == h and (
                    (proc[f]["situacao"] == "excluído" and not p.exists())
                    or (proc[f]["situacao"] == "alterado" and p.is_file() and sha(p) == proc[f]["sha256_versao_publica"])):
                decl += 1
            else:
                erro.append(f)
        check(not erro, f"{rec.name}: {iguais} idênticos, {decl} excluídos/alterados conforme PROCEDENCIA.csv, "
                        f"{len(erro)} sem explicação {erro[:3]}")

    print("3. Fontes usadas na coleta (manifest.json)")
    man = json.loads((ROOT / P / "manifest.json").read_text())
    iguais, decl, erro = 0, 0, []
    for f, h in man["sources_sha256"].items():
        p, k = ROOT / "paper_repro" / f, "paper_repro/" + f
        if sha(p) == h:
            iguais += 1
        elif k in proc and proc[k]["sha256_original"] == h and proc[k]["sha256_versao_publica"] == sha(p):
            decl += 1
        else:
            erro.append(f)
    check(not erro, f"{iguais} idênticas às usadas, {decl} alteradas só em comentários (PROCEDENCIA.csv), "
                    f"{len(erro)} sem explicação {erro[:3]}")

    print("4. Recálculo da análise a partir dos dados brutos")
    with tempfile.TemporaryDirectory() as tmp:
        r = subprocess.run([sys.executable, str(ROOT / "paper_repro/scripts/analisar_coleta.py"), str(ROOT / P),
                            "--saida", tmp, "--conferir"], capture_output=True, text=True)
        check(r.returncode == 0 and "CONFERÊNCIA OK" in r.stdout,
              "6 CSV de analysis/ recalculados e idênticos" if r.returncode == 0 else r.stdout[-300:] + r.stderr[-300:])

    print("5. Relatório de memória")
    sys.path[:0] = [str(ROOT / "paper_repro/scripts"), str(ROOT / "paper_repro/tools")]
    import memory_paper  # noqa: E402
    with tempfile.TemporaryDirectory() as tmp:
        memory_paper.write_report(Path(tmp), json.loads((ROOT / M / "memory_results.json").read_text()))
        same = (Path(tmp) / "report.md").read_bytes() == (ROOT / M / "report_public.md").read_bytes()
    caps = len(list((ROOT / M / "captures").glob("*.json")))
    check(same, f"report_public.md regenerado de memory_results.json é idêntico; {caps} registros de captura")

    print("6. Material sensível e material do artigo original")
    arquivos = [p for p in ROOT.rglob("*") if p.is_file() and not any(
        x in p.parts for x in (".git", ".venv", "vendor", "build", "__pycache__", ".pytest_cache", "preliminary"))]
    priv = [p for p in arquivos if p.name.startswith("private.")]
    check(not priv, f"nenhuma chave privada ({len(priv)} encontradas)")
    art = [p for p in arquivos if "article" in p.name or p.parent.name == "reference"]
    check(not art, f"nenhum arquivo de valores do artigo original ({len(art)} encontrados) {art[:3]}")
    return 1 if falhas else 0


if __name__ == "__main__":
    rc = main()
    print("\nRESULTADO:", "tudo conferido" if rc == 0 else f"{len(falhas)} falha(s)")
    sys.exit(rc)
