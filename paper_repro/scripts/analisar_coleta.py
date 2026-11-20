"""Análise de uma coleta de desempenho (resultados próprios; sem comparação com valores do artigo original).

Uso:
  python paper_repro/scripts/analisar_coleta.py <pasta da coleta>                    # grava <coleta>/analysis e figures
  python paper_repro/scripts/analisar_coleta.py <pasta da coleta> --saida <pasta>    # grava em outra pasta
  python paper_repro/scripts/analisar_coleta.py <pasta da coleta> --saida <pasta> --conferir
  python paper_repro/scripts/analisar_coleta.py --ultima preliminary|performance     # coleta mais recente
      recalcula a partir de raw/ e confere, byte a byte, os CSV recalculados com os de <coleta>/analysis/

Derivado de analyze_paper.py (versão acadêmica), mantendo só o cálculo sobre os dados próprios.

Validação (qualquer falha aborta): manifesto `complete`; config_id recalculado = gravado; uma saída por unidade do
plano, revalidada (biblioteca, preenchimento, chave, conjuntos, nº de medidas, coerência estatística, gerações de
chave); versão da biblioteca = manifesto; SHA-256 das chaves públicas = keys.json; SHA-256 da mensagem.
As chaves PRIVADAS de laboratório não são distribuídas; sua ausência é informada e não interrompe a análise.

Estatística:
  - por (biblioteca, chave, operação, conjunto): média das 5 execuções das médias por execução; o conjunto de 10 é
    calculado e marcado `discarded`;
  - valor agregado nas figuras: média simples dos conjuntos mantidos (100, 1000, 10000);
  - geração de chaves: média das gerações (1 por execução);
  - recursos (rusage de cada processo): RSS máximo e tempo de CPU.
"""
from __future__ import annotations

import argparse
import json
import statistics as st
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from paper_common import LIB_ORDER, ROOT, config_id, perf_dir, prelim_dir, rel, sha256_file  # noqa: E402
from paper_data import expectations, parse_bench  # noqa: E402

OPS = ["key_generation", "encrypt", "decrypt"]
OP_PT = {"key_generation": "geração de chaves", "encrypt": "cifração", "decrypt": "decifração"}
LANG_COLOR = {"C": "#2a78d6", "C++": "#eb6834", "Java": "#1baf7a", "JavaScript": "#eda100", "Python": "#e87ba4",
              "Rust": "#008300"}
CSVS = ["measurements.csv", "keygen.csv", "summary_sets.csv", "summary_keygen.csv", "resources.csv",
        "summary_resources.csv"]
RAIZ = "<RAIZ_DO_PROJETO>"  # marcador que substitui caminhos absolutos do ambiente original no manifesto


class ValidationError(RuntimeError):
    pass


def load_run(run_dir: Path) -> tuple[dict, list[dict], list[str]]:
    man = json.loads((run_dir / "manifest.json").read_text())
    if man.get("kind") != "paper-performance":
        raise ValidationError("não é uma coleta de desempenho")
    if man["status"] != "complete":
        raise ValidationError(f"coleta com status {man['status']!r} (retome com run_paper.py --resume)")
    cfg = dict(man["config"])
    if cfg["message_path"].startswith(RAIZ):
        cfg["message_path"] = str(ROOT) + cfg["message_path"][len(RAIZ):]
    if config_id(cfg) != man["config_id"]:
        raise ValidationError("config_id recalculado difere do gravado (configuração ou mensagem alterada)")
    if sha256_file(run_dir / "message.txt") != man["message_sha256"]:
        raise ValidationError("mensagem da coleta alterada")
    ausentes = []
    for k in man["keys"]["keys"]:
        for f, h in k["files_sha256"].items():
            p = run_dir / "keys" / str(k["bits"]) / f
            if not p.exists() and f.startswith("private."):
                ausentes.append(f"{k['bits']}/{f}")
                continue
            if sha256_file(p) != h:
                raise ValidationError(f"chave alterada: {k['bits']}/{f}")
    raw = run_dir / "raw"
    expected = {u["unit"] for u in man["plan"]}
    found = {p.name[:-4] for p in raw.glob("*.txt")}
    if found != expected:
        raise ValidationError(f"saídas faltando {sorted(expected - found)[:5]} / sobrando {sorted(found - expected)[:5]}")
    units = []
    for u in man["plan"]:
        try:
            parsed = parse_bench((raw / f"{u['unit']}.txt").read_text(), lib=u["lib"], padding=u["padding"],
                                 bits=u["bits"], **expectations(cfg, u))
        except ValueError as e:
            raise ValidationError(f"{u['unit']}: {e}") from e
        versions = man["implementations"][u["lib"]]["library_version"]
        if parsed["meta"]["library_version"] != versions:
            raise ValidationError(f"{u['unit']}: versão {parsed['meta']['library_version']} != manifesto {versions}")
        units.append({**u, **parsed})
    return man, units, ausentes


def sd(xs):
    return st.stdev(xs) if len(xs) > 1 else 0.0


def sort_key(name):
    return (LIB_ORDER.index(name) if name in LIB_ORDER else len(LIB_ORDER), name)


def tables(man, units):
    cfg = man["config"]
    meas, kg = [], []
    for u in units:
        for o in u["ops"]:
            meas.append({"run_id": man["run_id"], "config_id": man["config_id"], "execution": u["execution"],
                         "key_bits": u["bits"], "name": u["name"], "library_id": u["lib"], "variant": int(u["variant"]),
                         "padding": u["padding"], "operation": o["operation"], "set": o["set"], "n": o["n"],
                         "mean_ms": o["mean_s"] * 1e3, "sd_ms": o["sd_s"] * 1e3, "min_ms": o["min_s"] * 1e3,
                         "max_ms": o["max_s"] * 1e3, "total_s": o["total_s"],
                         "discarded": int(o["set"] in cfg["discard_sets"])})
        for k in u["keygen"]:
            kg.append({"run_id": man["run_id"], "unit": u["unit"],
                       "source": "experimento independente" if u.get("kind") == "keygen" else "embutida na unidade de cifração",
                       "execution": u["execution"], "key_bits": u["bits"], "name": u["name"],
                       "library_id": u["lib"], "variant": int(u["variant"]), "round": k["round"],
                       "ms": k["seconds"] * 1e3, "public_exponent": k.get("public_exponent", ""),
                       "modulus_bits": k.get("modulus_bits", "")})
    per_set = {}
    for m in meas:
        per_set.setdefault((m["name"], m["key_bits"], m["operation"], m["set"]), []).append(m)
    summary = []
    for (name, bits, op, s), rows in sorted(per_set.items(), key=lambda kv: (sort_key(kv[0][0]), kv[0][1:])):
        means = [r["mean_ms"] for r in sorted(rows, key=lambda r: r["execution"])]
        summary.append({"name": name, "key_bits": bits, "operation": op, "set": s, "executions": len(means),
                        "mean_of_execution_means_ms": st.fmean(means), "sd_between_executions_ms": sd(means),
                        "min_execution_mean_ms": min(means), "max_execution_mean_ms": max(means),
                        "mean_within_execution_sd_ms": st.fmean(r["sd_ms"] for r in rows),
                        "discarded": int(s in cfg["discard_sets"])})
    kg_sum = []
    by = {}
    for k in kg:
        by.setdefault((k["name"], k["key_bits"]), []).append(k)
    for (name, bits), rows in sorted(by.items(), key=lambda kv: (sort_key(kv[0][0]), kv[0][1])):
        v = [r["ms"] for r in rows]
        kg_sum.append({"name": name, "key_bits": bits, "source": rows[0]["source"], "samples": len(v),
                       "mean_ms": st.fmean(v), "sd_ms": sd(v), "cv": sd(v) / st.fmean(v), "median_ms": st.median(v),
                       "min_ms": min(v), "max_ms": max(v),
                       "public_exponents": " ".join(sorted({str(r["public_exponent"]) for r in rows})),
                       "modulus_bits": " ".join(sorted({str(r["modulus_bits"]) for r in rows}))})
    return meas, kg, summary, kg_sum


def resources(man) -> tuple[list[dict], list[dict]]:
    """RSS máximo e tempo de CPU de cada processo medido (rusage)."""
    rows = []
    for u in man["plan"]:
        info = man["units_done"].get(u["unit"], {})
        if "max_rss_kb" in info:
            rows.append({"unit": u["unit"], "kind": u.get("kind", "bench"), "name": u["name"], "key_bits": u["bits"],
                         "execution": u["execution"], "max_rss_mb": info["max_rss_kb"] / 1024,
                         "user_cpu_s": info["user_cpu_s"], "sys_cpu_s": info["sys_cpu_s"], "wall_s": info["seconds"]})
    by = {}
    for r in rows:
        by.setdefault((r["name"], r["key_bits"], r["kind"]), []).append(r)
    summ = [{"name": n, "key_bits": b, "kind": k, "processes": len(v), "mean_max_rss_mb": st.fmean(x["max_rss_mb"] for x in v),
             "max_max_rss_mb": max(x["max_rss_mb"] for x in v), "mean_wall_s": st.fmean(x["wall_s"] for x in v)}
            for (n, b, k), v in sorted(by.items(), key=lambda kv: (sort_key(kv[0][0]), kv[0][1], kv[0][2]))]
    return rows, summ


def aggregated(summary, kg_sum) -> dict:
    """(name, bits, op) -> média dos conjuntos mantidos (cifração/decifração) ou média das gerações."""
    sets = {}
    for s in summary:
        if not s["discarded"]:
            sets.setdefault((s["name"], s["key_bits"], s["operation"]), []).append(s["mean_of_execution_means_ms"])
    out = {k: st.fmean(v) for k, v in sets.items()}
    for k in kg_sum:
        out[(k["name"], k["key_bits"], "key_generation")] = k["mean_ms"]
    return out


def write_csv(path: Path, rows: list[dict]):
    import csv
    if not rows:
        return
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        for r in rows:
            w.writerow({k: (f"{v:.6g}" if isinstance(v, float) else v) for k, v in r.items()})


def figures(figdir: Path, cfg, rep, man) -> list[Path]:
    """Barras horizontais por operação e chave, ordenadas pelo tempo, com rótulo de valor (só dados próprios)."""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    figdir.mkdir(parents=True, exist_ok=True)
    lang = {lib: v["language"] for lib, v in cfg["libraries"].items()}
    label = {lib: v["name"] for lib, v in cfg["libraries"].items()}
    plt.rcParams.update({"font.size": 9, "axes.edgecolor": "#8a8a85", "axes.labelcolor": "#2b2b29",
                         "xtick.color": "#5c5c58", "ytick.color": "#2b2b29"})
    written = []
    for op in OPS:
        bits_list = [b for b in cfg["key_bits"] if any((lib, b, op) in rep for lib in cfg["libraries"])]
        if not bits_list:
            continue
        fig, axes = plt.subplots(1, len(bits_list), figsize=(max(4.6 * len(bits_list), 9.0), 4.6), squeeze=False)
        for ax, bits in zip(axes[0], bits_list):
            libs = sorted([lib for lib in cfg["libraries"] if (lib, bits, op) in rep], key=lambda x: rep[(x, bits, op)])
            vals = [rep[(lib, bits, op)] for lib in libs]
            ax.barh(range(len(libs)), vals, color=[LANG_COLOR[lang[x]] for x in libs], height=0.7, edgecolor="white", linewidth=2)
            for i, v in enumerate(vals):
                ax.text(v, i, f" {v:.5g}", va="center", fontsize=7.5, color="#2b2b29")
            ax.set_yticks(range(len(libs)), [label[x] for x in libs])
            ax.set_xlim(0, max(vals) * 1.3)
            ax.set_xlabel("Tempo médio (ms)")
            ax.set_title(f"Chave {bits} bits", fontsize=10)
            ax.grid(axis="x", color="#e4e4e0", linewidth=0.8)
            ax.set_axisbelow(True)
            for s in ("top", "right"):
                ax.spines[s].set_visible(False)
        handles = [plt.Rectangle((0, 0), 1, 1, color=c) for c in LANG_COLOR.values()]
        fig.legend(handles, list(LANG_COLOR), loc="lower center", ncol=6, frameon=False, bbox_to_anchor=(0.5, -0.02))
        fig.suptitle(f"Reprodução — {OP_PT[op]}\n{man['run_id']} · média de {cfg['executions']} execução(ões)", fontsize=10.5)
        fig.tight_layout(rect=(0, 0.07, 1, 1))
        p = figdir / f"reproduction_{op}.png"
        fig.savefig(p, dpi=150)
        plt.close(fig)
        written.append(p)
    return written


def analyze(run_dir: Path, out_dir: Path) -> tuple[Path, list[str]]:
    man, units, ausentes = load_run(run_dir)
    cfg = man["config"]
    meas, kg, summary, kg_sum = tables(man, units)
    res_rows, res_sum = resources(man)
    an = out_dir / "analysis"
    an.mkdir(parents=True, exist_ok=True)
    for name, rows in zip(CSVS, (meas, kg, summary, kg_sum, res_rows, res_sum)):
        write_csv(an / name, rows)
    figures(out_dir / "figures", cfg, aggregated(summary, kg_sum), man)
    return an, ausentes


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("run", nargs="?")
    ap.add_argument("--ultima", choices=["preliminary", "performance"], help="analisa a coleta criada por último")
    ap.add_argument("--saida", help="pasta de saída (padrão: a própria coleta)")
    ap.add_argument("--conferir", action="store_true", help="confere os CSV recalculados com os de <coleta>/analysis")
    a = ap.parse_args(argv)
    if a.ultima:
        base = prelim_dir() if a.ultima == "preliminary" else perf_dir()
        mans = list(base.glob("*/manifest.json"))
        if not mans:
            raise SystemExit(f"nenhuma coleta em {rel(base)}")
        run_dir = max(mans, key=lambda m: json.loads(m.read_text())["created_utc"]).parent
    elif a.run:
        run_dir = Path(a.run).resolve()
    else:
        ap.error("informe a pasta da coleta ou --ultima")
    out_dir = Path(a.saida).resolve() if a.saida else run_dir
    if out_dir == run_dir and (run_dir / "analysis").exists():
        raise SystemExit(f"{rel(run_dir)}/analysis já existe e não é sobrescrita; use --saida <pasta>")
    if a.conferir and out_dir == run_dir:
        raise SystemExit("--conferir exige --saida")
    try:
        an, ausentes = analyze(run_dir, out_dir)
    except ValidationError as e:
        raise SystemExit(f"VALIDAÇÃO FALHOU ({rel(run_dir)}): {e}")
    print(f"coleta validada: {rel(run_dir)}")
    if ausentes:
        print(f"chaves privadas ausentes (não distribuídas): {len(ausentes)} arquivo(s); conferidas só as públicas")
    print(f"análise gravada em: {rel(an)} e {rel(out_dir / 'figures')}")
    if a.conferir:
        ruins = [n for n in CSVS if (an / n).read_bytes() != (run_dir / "analysis" / n).read_bytes()]
        for n in CSVS:
            print(f"  {'IGUAL    ' if n not in ruins else 'DIFERENTE'} analysis/{n}")
        if ruins:
            raise SystemExit(f"CONFERÊNCIA FALHOU: {len(ruins)} arquivo(s) diferente(s)")
        print(f"CONFERÊNCIA OK: os {len(CSVS)} CSV recalculados são idênticos aos distribuídos")


if __name__ == "__main__":
    main()
