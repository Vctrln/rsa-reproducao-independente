"""Base comum do pipeline da reprodução do artigo: caminhos, protocolo, registro das 12 implementações, ambiente.

Grava só em results/paper_reproduction/.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

PAPER = Path(__file__).resolve().parents[1]          # paper_repro/
ROOT = PAPER.parent                                  # raiz do projeto
BUILD = PAPER / "build"
VENDOR = PAPER / "vendor"
PROTOCOL_DIR = PAPER / "protocol"
PY =ROOT / ".venv" / "bin" / "python"
NODE = VENDOR / "node-v20.19.0-linux-x64" / "bin" / "node"
BCJAR = VENDOR / "bcprov-jdk18on-1.79.jar"

def results_root() -> Path:
    """results/paper_reproduction/.
    PAPER_RESULTS_ROOT redireciona (usado pelos testes de integração, que não podem gravar em results/)."""
    return Path(os.environ.get("PAPER_RESULTS_ROOT", ROOT / "results" / "paper_reproduction"))


def perf_dir() -> Path:
    return results_root() / "performance"


def prelim_dir() -> Path:
    return results_root() / "preliminary"


def mem_dir() -> Path:
    return results_root() / "memory"


# Ordem da Tabela 1 do artigo.
LIB_ORDER = ["c_openssl", "c_libgcrypt", "cpp_botan", "cpp_cryptopp", "java_bouncycastle", "java_jca",
             "js_crypto", "js_forge", "py_cryptography", "py_pycryptodome", "rust_openssl", "rust_rustcrypto"]


def impl_argv(lib_id: str) -> list[str]:
    """Linha de comando de cada implementação (todas seguem implementations/CONTRACT.md)."""
    java = ["java", "-cp", f"{BUILD / 'java'}:{BCJAR}"]
    table = {
        "c_openssl": [str(BUILD / "c_openssl")],
        "c_libgcrypt": [str(BUILD / "c_libgcrypt")],
        "cpp_botan": [str(BUILD / "cpp_botan")],
        "cpp_cryptopp": [str(BUILD / "cpp_cryptopp")],
        "java_bouncycastle": java + ["paper.BouncyCastleBench"],
        "java_jca": java + ["paper.JcaBench"],
        "js_crypto": [str(NODE), str(PAPER / "implementations" / "js" / "crypto_bench.js")],
        "js_forge": [str(NODE), str(PAPER / "implementations" / "js" / "forge_bench.js")],
        "py_cryptography": [str(PY), str(PAPER / "implementations" / "python" / "cryptography_bench.py")],
        "py_pycryptodome": [str(PY), str(PAPER / "implementations" / "python" / "pycryptodome_bench.py")],
        "rust_openssl": [str(BUILD / "rust" / "release" / "rust_openssl")],
        "rust_rustcrypto": [str(BUILD / "rust" / "release" / "rust_rustcrypto")],
    }
    return table[lib_id]


def load_protocol() -> dict:
    with open(PROTOCOL_DIR / "protocol.toml", "rb") as f:
        return tomllib.load(f)


def resolve(profile: str = "full") -> dict:
    """Configuração efetiva: [protocol] + sobreposições do perfil. `full` = protocolo publicado sem alterações."""
    proto = load_protocol()
    if profile not in proto["profiles"]:
        raise SystemExit(f"perfil desconhecido: {profile} (opções: {', '.join(proto['profiles'])})")
    cfg = dict(proto["protocol"])
    prof = dict(proto["profiles"][profile])
    category = prof.pop("category")
    cfg.update(prof)
    cfg["profile"] = profile
    cfg["category"] = category
    cfg["libraries"] = {k: proto["libraries"][k] for k in LIB_ORDER}
    cfg["variants"] = proto.get("variants", {})
    cfg["message_path"] = str(PROTOCOL_DIR / cfg["message_file"])
    # plan_version 2: geração de chaves como experimento independente (unidades kg_*) e cifração/decifração sem
    # geração embutida (ed_*). Coletas anteriores (sem este campo) seguem válidas com o formato antigo.
    cfg["plan_version"] = 2
    return cfg


def config_id(cfg: dict) -> str:
    keys = ["id", "message_file", "key_bits", "iteration_sets", "discard_sets", "executions", "keygen_per_execution",
            "key_source", "cpu_core", "warmup_ops", "timer", "library_order"]
    blob = {k: cfg[k] for k in keys}
    blob["libraries"] = {k: v["padding"] for k, v in cfg["libraries"].items()}
    if cfg.get("plan_version", 1) >= 2:  # não altera o config_id das coletas anteriores
        blob["plan_version"] = cfg["plan_version"]
        blob["keygen_e"] = {k: v["keygen_e"] for k, v in cfg["libraries"].items()}
        blob["variants"] = {k: v["padding"] for k, v in cfg["variants"].items()}
    blob["message_sha256"] = sha256_file(cfg["message_path"])
    return hashlib.sha256(json.dumps(blob, sort_keys=True).encode()).hexdigest()[:12]


def sha256_file(p) -> str:
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def sh(cmd) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return (r.stdout or r.stderr).strip().splitlines()[0] if (r.stdout or r.stderr).strip() else ""
    except Exception as e:  # noqa: BLE001
        return f"indisponível ({e.__class__.__name__})"


def impl_versions() -> dict:
    out = {}
    for lib in LIB_ORDER:
        r = subprocess.run(impl_argv(lib) + ["version"], capture_output=True, text=True, timeout=120)
        if r.returncode != 0:
            raise RuntimeError(f"{lib}: `version` falhou: {r.stderr.strip()}")
        out[lib] = json.loads(r.stdout)
    return out


def binaries_sha256() -> dict:
    files = [BUILD / "c_openssl", BUILD / "c_libgcrypt", BUILD / "cpp_botan", BUILD / "cpp_cryptopp", BUILD / "rusage_exec",
             BUILD / "rust" / "release" / "rust_openssl", BUILD / "rust" / "release" / "rust_rustcrypto", BCJAR, NODE]
    files += sorted((BUILD / "java" / "paper").glob("*.class"))
    return {str(f.relative_to(PAPER)): sha256_file(f) for f in files}


def sources_sha256() -> dict:
    files = sorted(p for p in (PAPER / "implementations").rglob("*")
                   if p.is_file() and p.suffix in {".c", ".h", ".cpp", ".java", ".js", ".py", ".rs", ".toml", ".lock"})
    files += [PAPER / "tools" / "rusage_exec.c"]
    files += [PROTOCOL_DIR / "protocol.toml", PROTOCOL_DIR / "message_90B.txt"]
    return {str(f.relative_to(PAPER)): sha256_file(f) for f in files}


def environment() -> dict:
    cpu = ""
    try:
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.startswith("model name"):
                cpu = line.split(":", 1)[1].strip()
                break
    except OSError:
        pass
    mem = ""
    try:
        mem = Path("/proc/meminfo").read_text().splitlines()[0]
    except OSError:
        pass
    gov = Path("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor")
    return {
        "os": platform.platform(), "kernel": platform.release(), "machine": platform.machine(), "cpu": cpu,
        "cpus": os.cpu_count(), "memory": mem, "wsl": "microsoft" in platform.release().lower(),
        "cpu_governor": gov.read_text().strip() if gov.exists() else "indisponível",
        "gcc": sh(["gcc", "--version"]), "g++": sh(["g++", "--version"]), "javac": sh(["javac", "-version"]),
        "java": sh(["java", "-version"]), "node": sh([str(NODE), "--version"]), "rustc": sh(["rustc", "--version"]),
        "cargo": sh(["cargo", "--version"]), "python": sys.version.split()[0], "openssl_cli": sh(["openssl", "version"]),
        "pkg-config": {p: sh(["pkg-config", "--modversion", p]) for p in ("openssl", "libgcrypt", "botan-2", "libcrypto++")},
        "taskset": shutil.which("taskset") or "ausente", "gcore": shutil.which("gcore") or "ausente",
        "vendor_lock": (VENDOR / "deps.lock").read_text() if (VENDOR / "deps.lock").exists() else "ausente",
    }


def rel(p) -> str:
    try:
        return str(Path(p).resolve().relative_to(ROOT))
    except ValueError:
        return str(p)
