"""Coleta de desempenho do PROTOCOLO PUBLICADO (artigo §3.2) para as 12 bibliotecas.

Uso:
  python paper_repro/scripts/run_paper.py                       # perfil full = protocolo publicado (definitiva)
  python paper_repro/scripts/run_paper.py --profile pilot       # preliminar (1 execução, conjuntos 10 e 100)
  python paper_repro/scripts/run_paper.py --profile smoke       # preliminar rápido (2048 bits, conjuntos 10 e 20)
  python paper_repro/scripts/run_paper.py --dry-run             # plano + estimativa de duração, sem executar
  python paper_repro/scripts/run_paper.py --resume <pasta>      # completa uma coleta interrompida
  Subconjuntos (--libs, --bits, --executions, --sets, --no-pin, --no-variants) geram coleta `custom` (preliminar).

Unidade = (execução, chave, biblioteca) = 1 processo. Ordem: execução -> chave -> biblioteca, com a ordem das
bibliotecas girando a cada execução. Em cada processo: 1 geração de chave (medida), carga das chaves pré-geradas,
conjuntos 10, 100, 1000, 10000 nesta ordem (cifração e decifração de cada operação cronometradas individualmente).

Saída: results/paper_reproduction/performance/P-<UTC>/ (definitiva) ou results/paper_reproduction/preliminary/
<perfil>-P-<UTC>/. Nada é sobrescrito: cada coleta é uma pasta nova; cada
unidade só aparece em raw/ depois de validada (escrita atômica).
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import keys as keytool  # noqa: E402
from paper_common import (BUILD, LIB_ORDER, binaries_sha256, config_id, environment, impl_argv,  # noqa: E402
                          impl_versions, perf_dir, prelim_dir, rel, resolve, sha256_file, sources_sha256)
from paper_data import InvalidOutput, expectations, parse_bench  # noqa: E402


def utc() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def write_json_atomic(path: Path, obj) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(obj, indent=2, ensure_ascii=False))
    os.replace(tmp, path)


def unit_names(cfg) -> list[str]:
    return list(cfg["libraries"]) + list(cfg["variants"])


def plan(cfg) -> list[dict]:
    """Duas fases por execução: (1) GERAÇÃO de chaves — experimento independente (Figura 2), uma unidade por
    (chave, biblioteca), sem a variante (a geração não depende do preenchimento); (2) CIFRAÇÃO/DECIFRAÇÃO com as
    chaves pré-geradas (Figuras 3 e 4), uma unidade por (chave, biblioteca ou variante). Ordem das bibliotecas
    girando a cada execução."""
    names = unit_names(cfg)
    libs = list(cfg["libraries"])
    units = []
    for e in range(1, cfg["executions"] + 1):
        off = (e - 1) % len(names) if cfg["library_order"] == "rotate" else 0
        order = names[off:] + names[:off]
        if cfg.get("keygen_per_execution", 0) > 0:
            for bits in cfg["key_bits"]:
                for name in [n for n in order if n in libs]:
                    units.append({"unit": f"kg_e{e:02d}_{bits}_{name}", "kind": "keygen", "execution": e, "bits": bits,
                                  "name": name, "lib": name, "padding": cfg["libraries"][name]["padding"],
                                  "variant": False, "padding_arg": None})
        for bits in cfg["key_bits"]:
            for name in order:
                var = cfg["variants"].get(name)
                lib = var["base"] if var else name
                padding = var["padding"] if var else cfg["libraries"][name]["padding"]
                units.append({"unit": f"ed_e{e:02d}_{bits}_{name}", "kind": "encdec", "execution": e, "bits": bits,
                              "name": name, "lib": lib, "padding": padding, "variant": bool(var),
                              "padding_arg": var["padding"] if var else None})
    return units


def command(cfg, u, keydir: Path) -> list[str]:
    if u["kind"] == "keygen":
        cmd = impl_argv(u["lib"]) + ["keygen", "--bits", str(u["bits"]), "--keygen-rounds", str(cfg["keygen_per_execution"])]
    else:  # cifração/decifração com as chaves pré-geradas, sem geração embutida
        cmd = impl_argv(u["lib"]) + ["bench", "--keydir", str(keydir), "--bits", str(u["bits"]), "--msg",
                                     cfg["message_path"], "--sets", ",".join(map(str, cfg["iteration_sets"])),
                                     "--keygen-rounds", "0"]
    if u["padding_arg"]:
        cmd += ["--padding", u["padding_arg"]]
    if cfg["pin"]:
        cmd = ["taskset", "-c", str(cfg["cpu_core"])] + cmd
    return cmd


def run_unit(cfg, u, run_dir: Path) -> dict:
    raw = run_dir / "raw"
    t0 = time.monotonic()
    out, err, rus = (raw / f"{u['unit']}.{x}.tmp" for x in ("out", "err", "rusage"))
    with open(out, "w") as fo, open(err, "w") as fe:
        # rusage_exec: RSS máximo e CPU do programa medido (extensão: o artigo não mede consumo de memória)
        p = subprocess.run([str(BUILD / "rusage_exec"), str(rus)] + command(cfg, u, run_dir / "keys"),
                           stdout=fo, stderr=fe, stdin=subprocess.DEVNULL)
    secs = time.monotonic() - t0
    stdout, stderr = out.read_text(), err.read_text()
    ru = rus.read_text().split() if rus.exists() else ["0", "0", "0"]
    for f in (out, err, rus):
        f.unlink(missing_ok=True)
    if p.returncode != 0:
        (raw / f"{u['unit']}.failed.stderr").write_text(stderr)
        raise RuntimeError(f"{u['unit']}: saída {p.returncode}: {stderr.strip()[-300:]}")
    parse_bench(stdout, lib=u["lib"], padding=u["padding"], bits=u["bits"], **expectations(cfg, u))
    r = subprocess.CompletedProcess([], 0, stdout, stderr)
    tmp = raw / f"{u['unit']}.txt.tmp"
    tmp.write_text(r.stdout)
    os.replace(tmp, raw / f"{u['unit']}.txt")
    if r.stderr.strip():
        (raw / f"{u['unit']}.stderr").write_text(r.stderr)
    return {"seconds": round(secs, 3), "finished_utc": utc(), "max_rss_kb": int(ru[0]),
            "user_cpu_s": round(float(ru[1]), 3), "sys_cpu_s": round(float(ru[2]), 3)}


def check_pinning(core: int):
    if not shutil.which("taskset"):
        raise SystemExit("taskset indisponível: a coleta exige fixação de CPU (ou use --no-pin => coleta custom)")
    if core >= (os.cpu_count() or 1):
        raise SystemExit(f"núcleo {core} inexistente")
    r = subprocess.run(["taskset", "-c", str(core), "true"], capture_output=True)
    if r.returncode != 0:
        raise SystemExit(f"taskset -c {core} falhou: {r.stderr.decode().strip()}")


def adopt_existing(run_dir: Path, man: dict, cfg: dict, units: list[dict]) -> None:
    """Retomada: uma unidade fora de units_done cujo raw/<unit>.txt já existe (interrupção entre gravar o resultado
    e atualizar o manifesto) é revalidada com o MESMO validador da coleta. Válida -> registrada no manifesto sem ser
    executada de novo (a medição original é preservada). Inválida -> renomeada para .txt.rejected-<UTC> (nada é
    apagado) e a unidade é executada normalmente."""
    done = man["units_done"]
    for u in units:
        f = run_dir / "raw" / f"{u['unit']}.txt"
        if u["unit"] in done or not f.exists():
            continue
        try:
            parse_bench(f.read_text(), lib=u["lib"], padding=u["padding"], bits=u["bits"], **expectations(cfg, u))
        except (InvalidOutput, ValueError) as e:
            bad = f.with_name(f"{f.name}.rejected-{utc()}")
            os.replace(f, bad)
            print(f"{u['unit']}: resultado existente inválido ({e}); preservado em {bad.name} e unidade reexecutada",
                  flush=True)
            continue
        done[u["unit"]] = {"seconds": None, "finished_utc": None, "adopted_on_resume": utc()}
        write_json_atomic(run_dir / "manifest.json", man)
        print(f"{u['unit']}: resultado já gravado e válido; registrado sem reexecução", flush=True)


def collect(run_dir: Path, man: dict, cfg: dict, units: list[dict]):
    adopt_existing(run_dir, man, cfg, units)
    done = man["units_done"]
    todo = [u for u in units if u["unit"] not in done]
    print(f"{len(done)}/{len(units)} unidades já completas; {len(todo)} a executar em {rel(run_dir)}", flush=True)
    man["status"] = "running"
    write_json_atomic(run_dir / "manifest.json", man)
    try:
        for i, u in enumerate(todo, 1):
            info = run_unit(cfg, u, run_dir)
            done[u["unit"]] = info
            write_json_atomic(run_dir / "manifest.json", man)
            print(f"[{len(done)}/{len(units)}] {u['unit']}  {info['seconds']:.1f} s", flush=True)
    except KeyboardInterrupt:
        man["status"] = "interrupted"
        write_json_atomic(run_dir / "manifest.json", man)
        raise SystemExit(f"interrompida; retome com --resume {rel(run_dir)}")
    except Exception:
        man["status"] = "failed"
        write_json_atomic(run_dir / "manifest.json", man)
        raise
    man["status"] = "complete"
    man["finished_utc"] = utc()
    write_json_atomic(run_dir / "manifest.json", man)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--profile", default="full")
    ap.add_argument("--libs", help="subconjunto (ids de protocol.toml, incl. variantes) -> custom")
    ap.add_argument("--bits", help="ex.: 2048,4096 -> custom")
    ap.add_argument("--executions", type=int, help="-> custom")
    ap.add_argument("--sets", help="ex.: 10,100 -> custom")
    ap.add_argument("--no-pin", action="store_true", help="sem taskset -> custom")
    ap.add_argument("--no-variants", action="store_true", help="sem a variante Libgcrypt raw -> custom")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--resume")
    a = ap.parse_args(argv)

    if a.resume:
        run_dir = Path(a.resume).resolve()
        man = json.loads((run_dir / "manifest.json").read_text())
        if man["status"] == "complete":
            raise SystemExit("coleta já completa")
        if binaries_sha256() != man["binaries_sha256"] or sources_sha256() != man["sources_sha256"]:
            raise SystemExit("binários ou fontes mudaram desde o início da coleta: retomada recusada")
        cfg = man["config"]
        if cfg["pin"]:
            check_pinning(cfg["cpu_core"])
        collect(run_dir, man, cfg, man["plan"])
        return run_dir

    cfg = resolve(a.profile)
    custom = []
    if a.libs:
        names = a.libs.split(",")
        bad = [n for n in names if n not in cfg["libraries"] and n not in cfg["variants"]]
        if bad:
            raise SystemExit(f"bibliotecas desconhecidas: {bad}")
        cfg["libraries"] = {k: v for k, v in cfg["libraries"].items() if k in names}
        cfg["variants"] = {k: v for k, v in cfg["variants"].items() if k in names}
        custom.append("libs")
    if a.no_variants:
        cfg["variants"] = {}
        custom.append("no-variants")
    if a.bits:
        cfg["key_bits"] = [int(x) for x in a.bits.split(",")]
        custom.append("bits")
    if a.executions:
        cfg["executions"] = a.executions
        custom.append("executions")
    if a.sets:
        cfg["iteration_sets"] = [int(x) for x in a.sets.split(",")]
        custom.append("sets")
    cfg["pin"] = not a.no_pin
    if a.no_pin:
        custom.append("no-pin")
    if custom:
        cfg["category"] = "preliminar"
        cfg["custom"] = custom
    units = plan(cfg)
    nkg = sum(1 for u in units if u["kind"] == "keygen")
    print(f"Perfil {cfg['profile']}{' (custom: ' + ', '.join(custom) + ')' if custom else ''}: {len(units)} unidades "
          f"= {nkg} de geração de chaves ({cfg['executions']} execuções × {len(cfg['key_bits'])} chaves × "
          f"{len(cfg['libraries'])} bibliotecas) + {len(units) - nkg} de cifração/decifração ({cfg['executions']} × "
          f"{len(cfg['key_bits'])} × {len(unit_names(cfg))} bibliotecas/variantes); "
          f"conjuntos {cfg['iteration_sets']}")
    if a.dry_run:
        for u in units[: len(unit_names(cfg)) * len(cfg["key_bits"])]:
            print("  ", u["unit"])
        return None
    if cfg["pin"]:
        check_pinning(cfg["cpu_core"])

    if cfg["category"] == "definitiva":
        run_dir = perf_dir() / f"P-{utc()}"
    else:
        run_dir = prelim_dir() / f"{'custom' if custom else cfg['profile']}-P-{utc()}"
    if run_dir.exists():
        raise SystemExit(f"{run_dir} já existe")
    (run_dir / "raw").mkdir(parents=True)
    keymeta = keytool.make_keyset(run_dir / "keys", cfg["key_bits"])
    shutil.copy(cfg["message_path"], run_dir / "message.txt")
    man = {
        "run_id": run_dir.name, "kind": "paper-performance", "category": cfg["category"], "profile": cfg["profile"],
        "custom": custom, "created_utc": utc(), "status": "created", "config": cfg, "config_id": config_id(cfg),
        "message_sha256": sha256_file(cfg["message_path"]), "keys": keymeta, "environment": environment(),
        "implementations": impl_versions(), "binaries_sha256": binaries_sha256(), "sources_sha256": sources_sha256(),
        "plan": units, "units_done": {},
    }
    write_json_atomic(run_dir / "manifest.json", man)
    collect(run_dir, man, cfg, units)
    return run_dir


if __name__ == "__main__":
    d = main()
    if d:
        print(f"coleta completa: {rel(d)}\nanálise: python paper_repro/scripts/analisar_coleta.py {rel(d)}")
