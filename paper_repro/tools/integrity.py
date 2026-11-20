"""Registro e verificação de integridade das coletas definitivas (somente leitura das coletas).

Uso:
  python paper_repro/tools/integrity.py generate <pasta da coleta> [--compare-with <sha256 antigo>]
  python paper_repro/tools/integrity.py verify <arquivo .sha256> [...]
  python paper_repro/tools/integrity.py verify-all

`generate` grava, FORA da coleta, em results/paper_reproduction/integrity/:
  <id>.sha256  formato do `sha256sum` (caminhos relativos à raiz do projeto: `sha256sum -c` a partir dela também serve);
  <id>.json    escopo, categorias de cada arquivo, data, ferramenta, hash do próprio .sha256 e, com --compare-with,
               a comparação com uma linha de base anterior.
Todos os arquivos da pasta da coleta entram (nada é excluído; não há temporários nas coletas). Se o .sha256 já
existir, `generate` não sobrescreve: só verifica.
`verify` também acusa arquivos NOVOS na pasta da coleta (não listados), não só alterados ou ausentes.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "paper_repro" / "scripts"))


def results_root() -> Path:
    from paper_common import results_root as rr
    return rr()


def integrity_dir() -> Path:
    return results_root() / "integrity"


CATEGORIES = [  # (prefixo relativo à pasta da coleta, categoria)
    ("raw/", "dado bruto (medição)"),
    ("manifest.json", "manifesto da coleta"),
    ("message.txt", "mensagem de 90 B usada"),
    ("keys/", "chaves pré-geradas (laboratório)"),
    ("analysis/", "análise ORIGINAL v1 (derivado, gerado em 17/11 junto da coleta)"),
    ("figures/", "figuras ORIGINAIS v1 (derivado)"),
    ("captures/", "registro por captura (medição de memória)"),
    ("memory_results.json", "registro agregado da memória"),
    ("events.log", "registro de eventos da coleta de memória"),
    ("report.md", "relatório ORIGINAL da memória (derivado)"),
]


def category(rel_in_run: str) -> str:
    for p, c in CATEGORIES:
        if rel_in_run == p or rel_in_run.startswith(p):
            return c
    return "outro"


def sha256(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def listing(run: Path) -> list[Path]:
    return sorted(p for p in run.rglob("*") if p.is_file())


def rel(p: Path) -> str:
    """Caminho relativo à raiz do projeto (absoluto se estiver fora dela, p.ex. nos testes)."""
    p = p.resolve()
    try:
        return str(p.relative_to(ROOT))
    except ValueError:
        return str(p)


def read_sums(f: Path) -> dict[str, str]:
    out = {}
    for line in f.read_text().splitlines():
        if line.strip():
            h, path = line.split(maxsplit=1)
            out[path.lstrip("*")] = h
    return out


def verify(sums_file: Path) -> dict:
    meta_f = sums_file.with_suffix(".json")
    meta = json.loads(meta_f.read_text()) if meta_f.exists() else {}
    listed = read_sums(sums_file)
    changed, missing = [], []
    for path, h in listed.items():
        p = ROOT / path
        if not p.exists():
            missing.append(path)
        elif sha256(p) != h:
            changed.append(path)
    extra = []
    if meta.get("run_dir"):
        extra = [rel(p) for p in listing(ROOT / meta["run_dir"]) if rel(p) not in listed]
    if meta.get("sums_sha256") and sha256(sums_file) != meta["sums_sha256"]:
        changed.append(f"{rel(sums_file)} (o próprio registro de hashes)")
    return {"file": rel(sums_file), "listed": len(listed), "ok": len(listed) - len(changed) - len(missing),
            "changed": changed, "missing": missing, "extra": extra, "intact": not (changed or missing or extra)}


def generate(run: Path, compare_with: Path | None = None) -> tuple[Path, dict]:
    run = run.resolve()
    rid = run.name
    out = integrity_dir()
    out.mkdir(parents=True, exist_ok=True)
    sums_f = out / f"{rid}.sha256"
    if sums_f.exists():
        return sums_f, verify(sums_f)
    files = listing(run)
    lines = [f"{sha256(p)}  {rel(p)}" for p in files]
    sums_f.write_text("\n".join(lines) + "\n")
    cats: dict[str, int] = {}
    per_file = {}
    for p in files:
        c = category(str(p.relative_to(run)))
        cats[c] = cats.get(c, 0) + 1
        per_file[rel(p)] = c
    meta = {"run_id": rid, "run_dir": rel(run), "generated_utc": dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ"),
            "tool": "paper_repro/tools/integrity.py", "tool_sha256": sha256(Path(__file__)), "algorithm": "SHA-256",
            "scope": "todos os arquivos da pasta da coleta, recursivamente; nada excluído",
            "files": len(files), "categories": cats, "file_categories": per_file,
            "sums_sha256": sha256(sums_f),
            "how_to_verify": [f"python paper_repro/tools/integrity.py verify {rel(sums_f)}",
                              f"(alternativa, a partir da raiz do projeto) sha256sum -c {rel(sums_f)}"]}
    if compare_with:
        old = read_sums(compare_with)
        new = read_sums(sums_f)
        meta["baseline_comparison"] = {
            "baseline_file": str(compare_with), "baseline_entries": len(old),
            "identical_entries": sum(1 for k, v in old.items() if new.get(k) == v),
            "differing": sorted(k for k, v in old.items() if k in new and new[k] != v),
            "only_in_baseline": sorted(set(old) - set(new)), "only_now": sorted(set(new) - set(old))}
    sums_f.with_suffix(".json").write_text(json.dumps(meta, indent=1, ensure_ascii=False) + "\n")
    return sums_f, verify(sums_f)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("generate")
    g.add_argument("run")
    g.add_argument("--compare-with")
    v = sub.add_parser("verify")
    v.add_argument("files", nargs="+")
    sub.add_parser("verify-all")
    a = ap.parse_args(argv)
    if a.cmd == "generate":
        f, r = generate(Path(a.run), Path(a.compare_with) if a.compare_with else None)
        results = [r]
        print(f"registro: {rel(f)}")
    else:
        files = [Path(x) for x in a.files] if a.cmd == "verify" else sorted(integrity_dir().glob("*.sha256"))
        if not files:
            raise SystemExit("nenhum registro de integridade encontrado")
        results = [verify(f.resolve()) for f in files]
    bad = False
    for r in results:
        st = "ÍNTEGRA" if r["intact"] else "ALTERADA"
        print(f"{r['file']}: {st} — {r['ok']}/{r['listed']} conferem; alterados {len(r['changed'])}, ausentes "
              f"{len(r['missing'])}, novos não registrados {len(r['extra'])}")
        for k in ("changed", "missing", "extra"):
            for x in r[k][:20]:
                print(f"  {k}: {x}")
        bad |= not r["intact"]
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
