"""Harness comum Python do protocolo publicado — mesmo contrato e mesma saída do harness C/C++
(paper_repro/implementations/CONTRACT.md). Cada operação é cronometrada com time.perf_counter_ns (monotônico).
Média e DP populacional por conjunto. O coletor de lixo fica no padrão (ligado), como no pytest-benchmark padrão
usado pelos autores. Verificação fora do cronômetro; divergência sai com código 4.
"""
from __future__ import annotations

import math
import sys
import time
from pathlib import Path


def die(code: int, msg: str):
    sys.stderr.write(f"erro: {msg}\n")
    sys.stdout.flush()
    sys.exit(code)


def _parse(argv):
    if not argv:
        die(2, "uso: <version|bench|encrypt|decrypt|hold> [opções]")
    a = {"mode": argv[0], "keygen_rounds": 1, "padding": None}
    names = {"--keydir": "keydir", "--bits": "bits", "--msg": "msg", "--sets": "sets", "--padding": "padding",
             "--in": "in", "--keygen-rounds": "keygen_rounds"}
    it = iter(argv[1:])
    for o in it:
        if o not in names:
            die(2, f"opção desconhecida: {o}")
        try:
            a[names[o]] = next(it)
        except StopIteration:
            die(2, "opção sem valor")
    a["keygen_rounds"] = int(a["keygen_rounds"])
    if a["mode"] != "version":
        if int(a.get("bits", 0)) not in (2048, 3072, 4096):
            die(2, "--bits obrigatório")
        if a["mode"] != "keygen" and "keydir" not in a:
            die(2, "--keydir obrigatório")
        a["bits"] = int(a["bits"])
        a["key"] = lambda f: Path(a["keydir"]) / str(a["bits"]) / f
    return a


def _print_set(n, op, t):
    mean = sum(t) / len(t)
    sd = math.sqrt(sum((x - mean) ** 2 for x in t) / len(t))
    print(f"set,{n},{op},{len(t)},{mean:.9e},{sd:.9e},{min(t):.9e},{max(t):.9e},{sum(t):.9e}", flush=True)


def _keygen_rounds(lib, a):
    clock = time.perf_counter_ns
    for r in range(1, a["keygen_rounds"] + 1):
        t0 = clock()
        k = lib.keygen(a["bits"])
        t1 = clock()
        e, nbits = lib.keyinfo(k)
        print(f"keygen,{a['bits']},{r},{(t1 - t0) * 1e-9:.9e},{e},{nbits}", flush=True)


def run(lib, argv):
    """lib: meta(a), load(a), prepare(msg), enc() -> c, dec(c) -> p, cipher_bytes(c), cipher_from_bytes(b),
    plain_bytes(p), keygen(bits) -> chave, keyinfo(chave) -> (e, nbits) (fora do cronômetro)."""
    import json
    a = _parse(argv)
    if a["mode"] == "version":
        print(json.dumps(lib.meta(a)))
        return
    if a["mode"] == "keygen":  # experimento independente de geração de chaves
        print("meta," + json.dumps(lib.meta(a)), flush=True)
        _keygen_rounds(lib, a)
        print("done", flush=True)
        return
    if a["mode"] == "decrypt":
        lib.load(a)
        try:
            p = lib.dec(lib.cipher_from_bytes(bytes.fromhex(Path(a["in"]).read_text().strip())))
        except Exception as e:  # noqa: BLE001
            die(4, f"decifração falhou: {e}")
        print(lib.plain_bytes(p).hex())
        return
    if "msg" not in a:
        die(2, "--msg obrigatório")
    m = Path(a["msg"]).read_bytes()
    if a["mode"] == "encrypt":
        lib.load(a)
        lib.prepare(m)
        try:
            c = lib.enc()
        except Exception as e:  # noqa: BLE001
            die(3, f"cifração falhou: {e}")
        print(lib.cipher_bytes(c).hex())
        return
    if a["mode"] == "hold":
        lib.load(a)
        lib.prepare(m)
        print("READY " + lib.plain_bytes(lib.dec(lib.enc())).hex(), flush=True)
        sys.stdin.readline()
        return
    if a["mode"] != "bench":
        die(2, "modo desconhecido")
    if "sets" not in a:
        die(2, "--sets obrigatório")
    print("meta," + json.dumps(lib.meta(a)), flush=True)
    clock = time.perf_counter_ns
    _keygen_rounds(lib, a)
    lib.load(a)
    lib.prepare(m)
    enc, dec = lib.enc, lib.dec
    for s in a["sets"].split(","):
        n = int(s)
        te, td = [0.0] * n, [0.0] * n
        for i in range(n):
            t0 = clock()
            c = enc()
            t1 = clock()
            p = dec(c)
            t2 = clock()
            if lib.plain_bytes(p) != m:
                die(4, "verificação falhou: decifrado != mensagem")
            te[i] = (t1 - t0) * 1e-9
            td[i] = (t2 - t1) * 1e-9
        _print_set(n, "encrypt", te)
        _print_set(n, "decrypt", td)
    print("done", flush=True)


def meta(id_, library, version, padding, **extra):
    import platform
    return {"id": id_, "language": "Python", "library": library, "library_version": version,
            "runtime": f"{platform.python_implementation()} {platform.python_version()}", "padding": padding, **extra}
