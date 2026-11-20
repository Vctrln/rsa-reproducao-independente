"""Análise de despejo de memória (artigo §3.3 e §4.3) para as 12 bibliotecas do protocolo publicado.

Uso:  python paper_repro/scripts/memory_paper.py [--repetitions N] [--libs a,b] [--keep-dump] [--no-scan]

O que o ARTIGO descreve (§3.3): `gcore` (com sudo) sobre o PID de cada programa em execução, com a chave de 2048 bits;
busca de trechos PEM com `strings arquivo_dump | grep trecho_chave` e, com um script Python, da chave convertida em
bytes, dividida em blocos de 16 B, também na ordem invertida; tentativa de reconstrução (cabeçalho ASN.1 30 82).

O que o SCRIPT PUBLICADO pelos autores faz (Dump/script_dump.py, commit 1b3ffe0) — e por isso NÃO é reproduzido
como método principal: passa o NOME do arquivo ("private_2048.pem") como se fosse o conteúdo PEM, toma o ramo da
chave pública e serializa `public_bytes(SubjectPublicKeyInfo)`; ou seja, busca a CHAVE PÚBLICA (não secreta). Aqui
esse comportamento efetivo é replicado só como coluna separada ("script publicado"), para transparência.

Método desta reprodução (por captura):
  1. chave de laboratório de 2048 bits (openssl genpkey) + CHAVE DE CONTROLE que nunca entra em processo algum;
  2. processo `hold` da biblioteca: carrega a chave (no formato que a biblioteca usa), cifra e decifra uma vez,
     informa o texto decifrado (conferido) e espera; o script confere que está vivo antes e depois do gcore;
  3. buscas no dump (mmap):
     A. PEM: linhas Base64 do private.pem (equivale a `strings | grep` de cada linha);
     B. arquivo de chave efetivamente carregado (PEM, DER para Crypto++, S-expression para Libgcrypt), em blocos de 64 B;
     C. DER PKCS#8 da chave privada inteira e em blocos de 16 B, normal e invertido (§3.3);
     D. componentes secretos d, p, q, dp, dq, qinv (big-endian e invertidos = little-endian), inteiros e em blocos de 16 B;
     E. "script publicado": DER SubjectPublicKeyInfo (chave pública) inteiro, invertido e em blocos de 16 B;
     F. o mesmo de C e D para a chave de controle -> qualquer acerto torna a captura `inconclusiva`;
     Blocos com menos de `min_distinct` bytes distintos são ignorados (falsos positivos triviais), assim como
     trechos que também ocorrem na codificação da outra chave (estrutura ASN.1/PEM comum, não segredo; ver specific()).
  4. recuperação SEM conhecimento prévio da chave (a tentativa da §4.3, tornada verificável): (a) por estrutura —
     toda estrutura DER 30 82 ?? ?? 02 01 00 e todo cabeçalho PEM BEGIN … PRIVATE KEY no dump é interpretado como
     chave; (b) por fator — janelas alinhadas de 128 B, nas duas ordens de bytes, testadas como divisor do n público.
     Só conta se o módulo for o n público e a chave reconstruída decifrar um texto cifrado de teste.
Segurança: só chaves de laboratório; umask 077; dumps e chaves sobrescritos com zeros e apagados ao fim (salvo
--keep-dump); os resultados guardam só contagens. Saída: results/paper_reproduction/memory/PM-<UTC>/.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import mmap
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import keys as keytool  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import padding as P  # noqa: E402
from paper_common import (LIB_ORDER, PROTOCOL_DIR, environment, impl_argv, impl_versions,  # noqa: E402
                          load_protocol, mem_dir, rel)

KEY_FILE = {"cpp_cryptopp": "private.der", "c_libgcrypt": "private.sexp"}  # demais: private.pem
SMALL_BLOCK = load_protocol()["memory"].get("small_block_bytes", 8)  # blocos menores (artigo §4.3)
METHOD_VERSION = 3  # procedimento de busca/recuperação; a persistência incremental não altera o método


def provenance() -> dict:
    """SHA-256 dos binários e fontes das implementações e dos scripts desta análise (não altera o método)."""
    from paper_common import binaries_sha256, sha256_file, sources_sha256
    here = Path(__file__).resolve().parent
    return {"binaries_sha256": binaries_sha256(), "sources_sha256": sources_sha256(),
            "scripts_sha256": {f: sha256_file(here / f) for f in ("memory_paper.py", "paper_common.py")}}


def utc():
    return dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def blocks(b: bytes, size: int, min_distinct: int) -> list[bytes]:
    return [b[i:i + size] for i in range(0, len(b) - size + 1, size) if len(set(b[i:i + size])) >= min_distinct]


def int_bytes(v: int) -> bytes:
    return v.to_bytes((v.bit_length() + 7) // 8, "big")


def key_material(keydir: Path) -> dict:
    priv_pem = (keydir / "private.pem").read_bytes()
    key = serialization.load_pem_private_key(priv_pem, password=None)
    nums = key.private_numbers()
    comps = {"d": nums.d, "p": nums.p, "q": nums.q, "dp": nums.dmp1, "dq": nums.dmq1, "qinv": nums.iqmp}
    lines = [ln for ln in priv_pem.decode().splitlines() if ln and not ln.startswith("-----")]
    return {"key": key, "dir": keydir, "pem_lines": [ln.encode() for ln in lines], "der": (keydir / "private.der").read_bytes(),
            "spki": (keydir / "public.der").read_bytes(), "comps": {k: int_bytes(v) for k, v in comps.items()},
            "n": nums.public_numbers.n, "e": nums.public_numbers.e}


def java_words(be: bytes) -> bytes:
    """BigInteger do Java: int[] com a palavra mais significativa primeiro; cada int de 32 bits em little-endian."""
    be = b"\0" * (-len(be) % 4) + be
    return b"".join(be[i:i + 4][::-1] for i in range(0, len(be), 4))


def cpython_digits(be: bytes) -> bytes:
    """int do CPython: dígitos de 30 bits, o menos significativo primeiro, cada um num uint32 little-endian."""
    v, out = int.from_bytes(be, "big"), []
    while v:
        out.append((v & ((1 << 30) - 1)).to_bytes(4, "little"))
        v >>= 30
    return b"".join(out)


def multi_find(mm, patterns: list[bytes], chunk: int = 16 << 20, max_offsets: int = 64) -> dict[int, list[int]]:
    """Padrões presentes no dump -> offsets onde ocorrem (até `max_offsets` por padrão), numa só passagem:
    pré-filtro vetorizado pelos 4 primeiros bytes de cada padrão (numpy) e comparação exata dos candidatos.
    As chaves do resultado equivalem a {i : mm.find(p) != -1}."""
    import numpy as np
    keys: dict[int, list[int]] = {}
    for i, p in enumerate(patterns):
        keys.setdefault(int.from_bytes(p[:4], "little"), []).append(i)
    karr = np.array(sorted(keys), dtype=np.uint32)
    found: dict[int, list[int]] = {}
    size = len(mm)
    for start in range(0, size - 3, chunk):
        seg = np.frombuffer(mm[start:min(size, start + chunk + 3)], dtype=np.uint8).astype(np.uint32)  # cópia
        v = seg[:-3] | (seg[1:-2] << 8) | (seg[2:-1] << 16) | (seg[3:] << 24)
        for off in np.nonzero(np.isin(v, karr))[0].tolist():
            pos = start + off
            for i in keys[int(v[off])]:
                offs = found.get(i)
                if (offs is None or len(offs) < max_offsets) and mm[pos:pos + len(patterns[i])] == patterns[i]:
                    found.setdefault(i, []).append(pos)
    return found


def longest_contiguous(offsets: list[list[int] | None], step: int) -> int:
    """Maior sequência de blocos CONSECUTIVOS da chave encontrados em offsets consecutivos do dump
    (bloco k+1 em offset(bloco k) + step; step = +tamanho para ordem normal, -tamanho para invertida).
    Corresponde ao critério de contiguidade descrito na §4.3 do artigo."""
    best, prev = 0, {}
    for offs in offsets:
        cur = {}
        for o in offs or []:
            cur[o] = prev.get(o - step, 0) + 1
            best = max(best, cur[o])
        prev = cur
    return best


class Patterns:
    """Coleção nomeada de padrões; após multi_find, devolve contagens por grupo."""

    def __init__(self):
        self.pats: list[bytes] = []
        self.groups: dict[str, list[int]] = {}
        self.hit: dict[int, list[int]] = {}

    def add(self, group: str, pats):
        for p in pats:
            self.groups.setdefault(group, []).append(len(self.pats))
            self.pats.append(p)
        self.groups.setdefault(group, [])

    def run(self, mm):
        self.hit = multi_find(mm, self.pats)

    def n(self, group) -> int:
        return sum(1 for i in self.groups[group] if i in self.hit)

    def offsets(self, group) -> list[list[int] | None]:
        return [self.hit.get(i) for i in self.groups[group]]


LAYOUTS = {"be": lambda v: v, "le": lambda v: v[::-1], "java": java_words, "cpython": cpython_digits}


def specific(pats: list[bytes], other: bytes) -> list[bytes]:
    """Remove os trechos que também ocorrem na codificação da OUTRA chave: são estrutura (cabeçalhos ASN.1/PEM
    iguais em toda chave RSA-2048 de mesmo comprimento), não segredo. Sem isso, a chave de controle "aparecia" no
    dump quando seu DER tinha o mesmo comprimento do DER da chave de laboratório (blocos dos offsets 0 e 16)."""
    return [p for p in pats if p not in other and p[::-1] not in other]


def build_patterns(km: dict, keydir: Path, lib: str, bs: int, md: int, ctl: dict) -> Patterns:
    P_ = Patterns()
    kf_name = KEY_FILE.get(lib, "private.pem")
    ctl_pem = b"\n".join(ctl["pem_lines"])
    P_.add("pem", specific(km["pem_lines"], ctl_pem))
    P_.add("keyfile", specific(blocks((keydir / kf_name).read_bytes(), 64, md), (ctl["dir"] / kf_name).read_bytes()))
    der = km["der"]
    db = specific(blocks(der, bs, md), ctl["der"])
    P_.add("der_full", [der])
    P_.add("der_full_rev", [der[::-1]])
    P_.add("der_blocks", db)
    P_.add("der_blocks_rev", [b[::-1] for b in db])
    sbs = bs // 2 if not SMALL_BLOCK else SMALL_BLOCK
    sdb = specific(blocks(der, sbs, max(4, md - 2)), ctl["der"])
    P_.add("der_small", sdb)
    P_.add("der_small_rev", [b[::-1] for b in sdb])
    for name, v in km["comps"].items():
        for lay, f in LAYOUTS.items():
            P_.add(f"comp_{name}_{lay}", [f(v)])
        cb = blocks(v, bs, md)
        P_.add(f"compblk_{name}_be", cb)
        P_.add(f"compblk_{name}_le", [b[::-1] for b in cb])
    sp = km["spki"]
    P_.add("spki_full", [sp])
    P_.add("spki_full_rev", [sp[::-1]])
    P_.add("spki_blocks", blocks(sp, bs, md))
    cdb = specific(blocks(ctl["der"], bs, md), der)
    ctlp = cdb + [b[::-1] for b in cdb] + specific(ctl["pem_lines"], b"\n".join(km["pem_lines"]))
    for v in ctl["comps"].values():
        ctlp += [f(v) for f in LAYOUTS.values()] + blocks(v, bs, md) + [b[::-1] for b in blocks(v, bs, md)]
    P_.add("control", ctlp)
    return P_


def search(mm, km: dict, keydir: Path, lib: str, bs: int, md: int, ctl: dict) -> tuple[dict, int]:
    P_ = build_patterns(km, keydir, lib, bs, md, ctl)
    P_.run(mm)
    out = {"A_pem_lines": {"found": P_.n("pem"), "total": len(P_.groups["pem"])},
           "B_loaded_key_file_64B": {"file": KEY_FILE.get(lib, "private.pem"), "found": P_.n("keyfile"),
                                     "total": len(P_.groups["keyfile"])},
           "C_pkcs8_der": {"full": bool(P_.n("der_full")), "full_reversed": bool(P_.n("der_full_rev")),
                           "blocks_found": P_.n("der_blocks"), "blocks_reversed_found": P_.n("der_blocks_rev"),
                           "blocks_total": len(P_.groups["der_blocks"]),
                           "longest_consecutive_blocks": longest_contiguous(P_.offsets("der_blocks"), bs),
                           "longest_consecutive_blocks_reversed": longest_contiguous(P_.offsets("der_blocks_rev"), -bs),
                           "small_block_bytes": len(P_.pats[P_.groups["der_small"][0]]) if P_.groups["der_small"] else 0,
                           "small_blocks_found": P_.n("der_small"), "small_blocks_reversed_found": P_.n("der_small_rev"),
                           "small_blocks_total": len(P_.groups["der_small"])},
           "D_components": {name: {**{f"full_{lay}": bool(P_.n(f"comp_{name}_{lay}")) for lay in LAYOUTS},
                                   "blocks_be": P_.n(f"compblk_{name}_be"), "blocks_le": P_.n(f"compblk_{name}_le"),
                                   "blocks_total": len(P_.groups[f"compblk_{name}_be"])} for name in km["comps"]},
           "E_published_script_public_key": {"full": bool(P_.n("spki_full")), "full_reversed": bool(P_.n("spki_full_rev")),
                                             "blocks_found": P_.n("spki_blocks"), "blocks_total": len(P_.groups["spki_blocks"])}}
    return out, P_.n("control")


def prime_scan(path: Path, n: int, plen: int = 128, max_zero_words: int = 3, chunk_words: int = 4 << 20) -> dict:
    """Busca às cegas de um fator de n (sem usar p nem q) em janelas de 128 B alinhadas a 8 B, big e little endian.

    Pré-filtro vetorizado: um primo aleatório de 1024 bits ocupa 16 palavras de 8 B e quase nunca tem mais de 3
    palavras com algum byte zero (P ≈ 0,998); ponteiros, código e texto quase sempre têm. Só as janelas que passam
    (e têm o bit mais significativo ligado e são ímpares) são testadas com n % x. Cobertura do método: inteiros
    armazenados como sequência contígua de bytes (BIGNUM/limbs de 64 bits); não cobre dígitos de 28/30/32 bits."""
    import numpy as np
    t0 = time.monotonic()
    words = plen // 8
    tested = 0

    def scan(mm):  # função interna: as views numpy do mmap morrem no retorno, antes de o mmap ser fechado
        nonlocal tested
        a = np.frombuffer(mm, dtype=np.uint8)
        nwords = len(a) // 8
        for ws in range(0, nwords, chunk_words):
            we = min(nwords, ws + chunk_words + words - 1)
            zero = (a[ws * 8:we * 8].reshape(-1, 8) == 0).any(axis=1).astype(np.int32)
            if len(zero) < words:
                break
            c = np.concatenate(([0], np.cumsum(zero)))
            zcount = c[words:] - c[:-words]                 # palavras com zero em cada janela de 16
            for i in np.nonzero(zcount <= max_zero_words)[0].tolist():
                o = (ws + i) * 8
                w = mm[o:o + plen]
                for order in ("big", "little"):
                    msb, lsb = (w[0], w[-1]) if order == "big" else (w[-1], w[0])
                    if msb < 0x80 or not lsb & 1:
                        continue
                    x = int.from_bytes(w, order)
                    tested += 1
                    if n % x == 0 and 1 < x < n:
                        return o, order, x
        return None

    with open(path, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        hit = scan(mm)
    secs = round(time.monotonic() - t0, 1)
    if hit:
        return {"performed": True, "found": True, "offset": hit[0], "byte_order": hit[1], "candidates_tested": tested,
                "seconds": secs, "factor": hit[2]}
    return {"performed": True, "found": False, "candidates_tested": tested, "seconds": secs}


def structure_scan(path: Path, n: int, chunk: int = 64 << 20) -> dict:
    """Recuperação às cegas por ESTRUTURA (sem usar a chave conhecida), como a tentativa do artigo (§4.3):
      - DER: toda ocorrência de 30 82 ?? ?? 02 01 00 (SEQUENCE longa + INTEGER versão 0 = PKCS#8 ou PKCS#1)
        é interpretada como chave privada DER;
      - PEM: todo cabeçalho -----BEGIN (RSA )PRIVATE KEY----- é interpretado com o texto que o segue.
    Uma chave só conta se o módulo for o n público e a prova de decifração passar (feita pelo chamador)."""
    import numpy as np
    from cryptography.hazmat.primitives.asymmetric import rsa
    t0 = time.monotonic()
    tried = {"der": 0, "pem": 0}

    def try_key(blob: bytes, kind: str):
        tried[kind] += 1
        try:
            k = (serialization.load_der_private_key(blob, password=None) if kind == "der"
                 else serialization.load_pem_private_key(blob, password=None))
        except Exception:  # noqa: BLE001
            return None
        if isinstance(k, rsa.RSAPrivateKey) and k.private_numbers().public_numbers.n == n:
            return k.private_numbers().p
        return None

    with open(path, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        size = len(mm)
        for start in range(0, size, chunk):
            seg = np.frombuffer(mm[start:min(size, start + chunk + 7)], dtype=np.uint8)
            if len(seg) < 7:
                break
            m = ((seg[:-6] == 0x30) & (seg[1:-5] == 0x82) & (seg[4:-2] == 0x02) & (seg[5:-1] == 0x01) & (seg[6:] == 0x00))
            for off in np.nonzero(m)[0].tolist():
                pos = start + off
                ln = int.from_bytes(mm[pos + 2:pos + 4], "big") + 4
                if ln < 600 or pos + ln > size:
                    continue
                p = try_key(mm[pos:pos + ln], "der")
                if p:
                    return {"found": True, "method": "DER (30 82 … 02 01 00)", "offset": pos, "tried": tried,
                            "seconds": round(time.monotonic() - t0, 1), "factor": p}
        for hdr in (b"-----BEGIN PRIVATE KEY-----", b"-----BEGIN RSA PRIVATE KEY-----"):
            pos = mm.find(hdr)
            while pos != -1:
                end = mm.find(b"-----END", pos + len(hdr), pos + 8192)
                if end != -1:
                    tail = mm.find(b"-----", end + 8, end + 64)
                    p = try_key(mm[pos:tail + 5] if tail != -1 else mm[pos:end + 40], "pem")
                    if p:
                        return {"found": True, "method": "PEM (cabeçalho BEGIN)", "offset": pos, "tried": tried,
                                "seconds": round(time.monotonic() - t0, 1), "factor": p}
                pos = mm.find(hdr, pos + 1)
    return {"found": False, "tried": tried, "seconds": round(time.monotonic() - t0, 1)}


def prove_recovery(km: dict, p: int) -> bool:
    """Reconstrói a chave a partir de um fator e decifra um texto cifrado pela chave pública verdadeira."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    n, e = km["n"], km["e"]
    q = n // p
    d = pow(e, -1, (p - 1) * (q - 1))
    rec = rsa.RSAPrivateNumbers(p, q, d, d % (p - 1), d % (q - 1), pow(q, -1, p), rsa.RSAPublicNumbers(e, n)).private_key()
    msg = b"prova de recuperacao"
    ct = km["key"].public_key().encrypt(msg, P.PKCS1v15())
    return rec.decrypt(ct, P.PKCS1v15()) == msg


def secure_remove(path: Path):
    if path.is_file():
        try:
            with open(path, "r+b") as f:
                size = os.fstat(f.fileno()).st_size
                for _ in range(0, size, 1 << 20):
                    f.write(b"\0" * min(1 << 20, size - f.tell()))
                f.flush()
                os.fsync(f.fileno())
        finally:
            path.unlink()
    elif path.is_dir():
        for p in path.rglob("*"):
            if p.is_file():
                secure_remove(p)
        shutil.rmtree(path, ignore_errors=True)


def classify(r: dict, ctl: int, recovered: bool) -> str:
    if ctl:
        return "inconclusivo (acerto na chave de controle)"
    if recovered:
        return "chave recuperada sem conhecimento prévio"
    c = r["C_pkcs8_der"]
    comps = r["D_components"].values()
    if (c["full"] or any(x[f"full_{lay}"] for x in comps for lay in LAYOUTS)
            or r["A_pem_lines"]["found"] == r["A_pem_lines"]["total"]):
        return "material secreto completo presente"
    frag = (r["A_pem_lines"]["found"] + r["B_loaded_key_file_64B"]["found"] + c["blocks_found"] + c["blocks_reversed_found"]
            + sum(x["blocks_be"] + x["blocks_le"] for x in comps))
    return "fragmentos encontrados" if frag else "nenhum fragmento encontrado pelo método"


def capture(lib: str, keydir: Path, msg: Path, work: Path, gcore: str, tag: str) -> tuple[Path | None, dict]:
    info = {"lib": lib}
    p = subprocess.Popen(impl_argv(lib) + ["hold", "--keydir", str(keydir.parent), "--bits", "2048", "--msg", str(msg)],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        line = p.stdout.readline().strip()
        info["decrypted_ok"] = line == "READY " + msg.read_bytes().hex()
        if not info["decrypted_ok"]:
            info["error"] = f"processo não confirmou a decifração: {line[:60]!r} {p.stderr.read()[-200:] if p.poll() is not None else ''}"
            return None, info
        info["alive_before"] = p.poll() is None
        t0 = time.monotonic()
        g = subprocess.run([gcore, "-o", str(work / f"dump-{tag}"), str(p.pid)], capture_output=True, text=True, timeout=600)
        info["gcore_seconds"] = round(time.monotonic() - t0, 1)
        info["gcore_returncode"] = g.returncode
        info["alive_after"] = p.poll() is None
        dump = work / f"dump-{tag}.{p.pid}"
        if g.returncode != 0 or not dump.exists():
            info["error"] = f"gcore falhou: {g.stderr.strip()[-300:]}"
            return None, info
        info["dump_bytes"] = dump.stat().st_size
        return dump, info
    finally:
        if p.poll() is None:
            try:
                p.stdin.write("\n")
                p.stdin.flush()
                p.wait(timeout=60)
            except Exception:  # noqa: BLE001
                p.kill()
        info["exit_code"] = p.returncode


def preflight(gcore: str | None) -> dict:
    info = {"gcore": gcore, "ptrace_scope": None}
    yama = Path("/proc/sys/kernel/yama/ptrace_scope")
    info["ptrace_scope"] = int(yama.read_text()) if yama.exists() else "sem Yama (kernel WSL)"
    if not gcore:
        info["probe"] = "gcore ausente"
        return info
    tmp = Path(tempfile.mkdtemp(prefix="paper-gcore-probe-"))
    child = subprocess.Popen(["sleep", "30"])
    try:
        r = subprocess.run([gcore, "-o", str(tmp / "p"), str(child.pid)], capture_output=True, text=True, timeout=60)
        info["probe"] = "ok" if r.returncode == 0 and any(tmp.iterdir()) else f"falhou: {r.stderr.strip()[-200:]}"
    finally:
        child.kill()
        secure_remove(tmp)
    return info


def summarize(res: dict) -> dict:
    """Agrega as capturas por biblioteca (usado no relatório de memória e no relatório final)."""
    out = {}
    for c in res["captures"]:
        d = out.setdefault(c["lib"], {"captures": 0, "recovered": 0, "complete": 0, "methods": set(), "classes": set(),
                                      "control_hits": 0, "failures": 0})
        d["captures"] += 1
        d["classes"].add(c["classification"])
        if "search" not in c:
            d["failures"] += 1
            continue
        d["control_hits"] += c["control_hits"]
        rec = c.get("recovery", {})
        if rec.get("proved"):
            d["recovered"] += 1
            d["methods"].update(rec.get("methods_succeeded", []))
        if c["classification"] in ("chave recuperada sem conhecimento prévio", "material secreto completo presente"):
            d["complete"] += 1 if c["classification"] == "material secreto completo presente" or _complete(c["search"]) else 0
    for d in out.values():
        d["methods"], d["classes"] = sorted(d["methods"]), sorted(d["classes"])
    return dict(sorted(out.items(), key=lambda kv: LIB_ORDER.index(kv[0])))


def _complete(s: dict) -> bool:
    return (s["C_pkcs8_der"]["full"] or s["A_pem_lines"]["found"] == s["A_pem_lines"]["total"]
            or any(v[f"full_{lay}"] for v in s["D_components"].values() for lay in LAYOUTS))


def write_report(out: Path, res: dict):
    status = res.get("status", "complete")
    plan_n = len(res.get("plan", [])) or len(res["captures"])
    L = [f"# Análise de memória — {res['run_id']}", ""]
    if status != "complete" or res.get("pending"):
        L += [f"> ⚠️ **PARCIAL** — status `{status}`, {len(res['captures'])}/{plan_n} capturas concluídas. "
              f"Pendentes: {', '.join(res.get('pending', [])) or '—'}. Este relatório NÃO representa a análise completa "
              "das 12 implementações.", ""]
    if res.get("failed_attempts"):
        L += ["Tentativas que falharam (não contam como capturas): " +
              "; ".join(f"{f.get('tag', f.get('lib'))}: {f.get('error', '?')[:120]}" for f in res["failed_attempts"]), ""]
    if res.get("integrity_problems"):
        L += ["**Problemas de integridade:** " + "; ".join(res["integrity_problems"]), ""]
    L += [
         f"Método v{res.get('method_version', 1)} · gcore: {res['preflight']['gcore']} · ptrace_scope: {res['preflight']['ptrace_scope']} · "
         f"chave de 2048 bits · {res['repetitions']} captura(s) por biblioteca · blocos de {res['block_bytes']} B "
         f"(mín. {res['min_distinct']} bytes distintos; trechos estruturais comuns às duas chaves excluídos).", "",
         "**Métodos.** A = linhas PEM (`strings | grep`); B = arquivo de chave carregado pela biblioteca (blocos de 64 B); "
         "C = DER PKCS#8 inteiro / blocos de 16 B normais + invertidos (§3.3), maior sequência de blocos consecutivos em "
         "offsets consecutivos (normal/invertida) e contagem com blocos de 8 B (§4.3); D = componentes secretos d, p, q, dp, dq, qinv "
         "inteiros, nos layouts be (big-endian), le (little-endian), java (int[]) e cpython (dígitos de 30 bits); "
         "E = o que o script publicado pelos autores efetivamente busca (chave PÚBLICA; inteira ou nº de blocos); "
         "Recuperação = às cegas, sem usar a chave conhecida: por estrutura (DER 30 82 … 02 01 00 / PEM BEGIN) ou por "
         "fator de n em janelas alinhadas; só conta se a chave reconstruída decifrar um texto de teste. "
         "Controle = nº de acertos de uma chave que nunca foi carregada (tem de ser 0).", "",
         "| Biblioteca | Rep. | Dump (MB) | A PEM | B arquivo | C DER (inteiro / blocos) | D componentes inteiros | E pública | Controle | Recuperação | Classificação |",
         "|---|---|---|---|---|---|---|---|---|---|---|"]
    for c in res["captures"]:
        if "search" not in c:
            L.append(f"| {c['lib']} | {c['repetition']} | — | | | | | | | | falha: {c.get('error', '?')[:80]} |")
            continue
        s = c["search"]
        cd = s["C_pkcs8_der"]
        comps = [k + "(" + "/".join(lay for lay in LAYOUTS if v[f"full_{lay}"]) + ")"
                 for k, v in s["D_components"].items() if any(v[f"full_{lay}"] for lay in LAYOUTS)]
        rec = c["recovery"]
        rtxt = (("sim: " + ", ".join(rec["methods_succeeded"])) if rec.get("proved") else "não") if rec.get("performed") else "não feita"
        L.append(f"| {c['lib']} | {c['repetition']} | {c['dump_bytes'] / 1e6:.0f} | {s['A_pem_lines']['found']}/{s['A_pem_lines']['total']} | "
                 f"{s['B_loaded_key_file_64B']['found']}/{s['B_loaded_key_file_64B']['total']} | "
                 f"{'sim' if cd['full'] else 'não'} / {cd['blocks_found']}+{cd['blocks_reversed_found']}inv de {cd['blocks_total']}; "
                 f"contíguos {cd.get('longest_consecutive_blocks', '?')}/{cd.get('longest_consecutive_blocks_reversed', '?')}inv; "
                 f"{cd.get('small_block_bytes', '?')} B: {cd.get('small_blocks_found', '?')}+{cd.get('small_blocks_reversed_found', '?')}inv "
                 f"de {cd.get('small_blocks_total', '?')} | "
                 f"{', '.join(comps) or 'nenhum'} | {'inteira' if s['E_published_script_public_key']['full'] else s['E_published_script_public_key']['blocks_found']} | "
                 f"{c['control_hits']} | {rtxt} | {c['classification']} |")
    L += ["", "## Resumo por biblioteca (todas as repetições)", "",
          "| Biblioteca | Capturas | Recuperada às cegas | Material secreto completo | Classificações |",
          "|---|---|---|---|---|"]
    for lib, rows in summarize(res).items():
        L.append(f"| {lib} | {rows['captures']} | {rows['recovered']}/{rows['captures']} ({', '.join(rows['methods']) or '—'}) | "
                 f"{rows['complete']}/{rows['captures']} | {'; '.join(rows['classes'])} |")
    L += ["", "## Limites", "",
          "- \"Não encontrado\" significa só \"não encontrado por este método\" (ex.: inteiros do CPython e do forge usam "
          "dígitos de 30/28 bits, que não aparecem como sequência de bytes). \"Encontrado\" não prova vulnerabilidade "
          "explorável: o dump exige privilégio sobre o processo.",
          "- O tamanho do dump do gcore NÃO é o consumo de RAM: o gcore grava as regiões mapeadas (bibliotecas, heap reservado, pilhas).",
          "- Um instante de captura por processo, logo após uma cifração e uma decifração; o artigo não informa em que "
          "momento capturou nem quantas vezes.",
          "- Coluna E: o script publicado busca a chave PÚBLICA (ver docstring de memory_paper.py); encontrá-la não "
          "expõe segredo algum. Está aqui só para mostrar o que aquele script mediria."]
    (out / "report.md").write_text("\n".join(L) + "\n")


def work_root() -> Path:
    """Diretório de trabalho (chaves de laboratório e dumps) FORA de /tmp: o Ubuntu esvazia /tmp no boot
    (tmpfiles.d `D /tmp`) apagando os arquivos sem sobrescrita segura. Aqui eles sobrevivem a um reinício e são
    apagados com segurança na retomada ou no descarte. PAPER_MEMWORK redireciona (testes)."""
    return Path(os.environ.get("PAPER_MEMWORK", Path(__file__).resolve().parents[1] / ".memwork"))


def write_json_atomic(path: Path, obj) -> None:
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "w") as f:
        f.write(json.dumps(obj, indent=2, ensure_ascii=False))
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def plan_captures(libs: list[str], repetitions: int) -> list[dict]:
    """Ordem fixa: repetição -> biblioteca, com a ordem das bibliotecas girando a cada repetição."""
    out = []
    for rep in range(1, repetitions + 1):
        off = (rep - 1) % len(libs)
        for lib in libs[off:] + libs[:off]:
            out.append({"tag": f"{lib}-r{rep}", "lib": lib, "repetition": rep})
    return out


def load_captures(out: Path, plan: list[dict]) -> tuple[dict, list[str]]:
    """Capturas concluídas (captures/<tag>.json) e problemas de integridade (JSON inválido, tag fora do plano,
    biblioteca/repetição divergente). Falhas ficam em captures/<tag>.attemptN.failed.json e não contam como concluídas."""
    known = {c["tag"]: c for c in plan}
    done, problems = {}, []
    for f in sorted((out / "captures").glob("*.json")):
        if f.name.endswith(".failed.json"):
            continue
        tag = f.name[:-5]
        try:
            c = json.loads(f.read_text())
        except (OSError, ValueError) as e:
            problems.append(f"{f.name}: JSON inválido ({e})")
            continue
        if tag not in known:
            problems.append(f"{f.name}: captura fora do plano")
        elif c.get("lib") != known[tag]["lib"] or c.get("repetition") != known[tag]["repetition"]:
            problems.append(f"{f.name}: biblioteca/repetição divergente do plano")
        elif "search" not in c:
            problems.append(f"{f.name}: captura sem resultado de busca")
        else:
            done[tag] = c
    return done, problems


def failed_attempts(out: Path) -> list[dict]:
    return [json.loads(f.read_text()) for f in sorted((out / "captures").glob("*.failed.json"))]


def assemble(out: Path, header: dict) -> dict:
    """memory_results.json = cabeçalho + capturas concluídas NA ORDEM DO PLANO + tentativas que falharam.
    Reconstruído sempre a partir dos arquivos por captura (fonte única; sem duplicação)."""
    done, problems = load_captures(out, header["plan"])
    res = dict(header)
    res["captures"] = [done[c["tag"]] for c in header["plan"] if c["tag"] in done]
    res["failed_attempts"] = failed_attempts(out)
    res["pending"] = [c["tag"] for c in header["plan"] if c["tag"] not in done]
    res["integrity_problems"] = problems
    res["progress"] = f"{len(res['captures'])}/{len(header['plan'])}"
    return res


def persist(out: Path, header: dict) -> dict:
    res = assemble(out, header)
    write_json_atomic(out / "memory_results.json", res)
    write_report(out, res)
    return res


def event(out: Path, msg: str) -> None:
    with open(out / "events.log", "a") as f:
        f.write(f"{utc()} {msg}\n")
        f.flush()
        os.fsync(f.fileno())


class Lock:
    """Trava exclusiva ATÔMICA por análise: flock(LOCK_EX | LOCK_NB) do kernel sobre work/lock. Só um processo a
    obtém; o kernel a libera sozinho quando o processo termina, inclusive por SIGKILL ou encerramento do sistema,
    então não existe trava "órfã" a adivinhar. O arquivo não é apagado (apagá-lo abriria uma janela de corrida)."""

    def __init__(self, work: Path):
        import fcntl
        self.path = work / "lock"
        self.fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            holder = os.pread(self.fd, 64, 0).decode(errors="replace").split()
            os.close(self.fd)
            raise SystemExit(f"outra execução (pid {holder[0] if holder else '?'}) já está usando {work}; nada foi alterado")
        os.ftruncate(self.fd, 0)
        os.pwrite(self.fd, f"{os.getpid()} {utc()}\n".encode(), 0)

    def release(self):
        if self.fd is not None:
            os.close(self.fd)  # fechar o descritor libera o flock
            self.fd = None


def acquire_lock(work: Path) -> Lock:
    return Lock(work)


def shred_stale_dumps(work: Path) -> int:
    """Dumps deixados por uma execução interrompida: nunca são reutilizados (a captura é refeita); apagados com segurança."""
    n = 0
    for d in work.glob("dump-*"):
        secure_remove(d)
        n += 1
    return n


def key_fingerprint(km: dict) -> str:
    import hashlib
    return hashlib.sha256(km["n"].to_bytes(256, "big")).hexdigest()[:16]


def rep_keys(work: Path, rep: int, out: Path) -> tuple[Path, Path, bool]:
    """Chave de laboratório e chave de controle da repetição. Reutilizadas se já existirem (retomada: a repetição
    continua com a MESMA chave); geradas se ausentes (registrado no evento e na captura pela impressão digital)."""
    lab, ctl = work / f"lab{rep}", work / f"ctl{rep}"
    created = False
    for d in (lab, ctl):
        if not (d / "2048" / "private.pem").exists():
            if d.exists():
                secure_remove(d)
            keytool.make_keyset(d, [2048])
            created = True
    return lab / "2048", ctl / "2048", created


def analyze_dump(dump: Path, km: dict, ctl: dict, labdir: Path, lib: str, bs: int, md: int, no_scan: bool) -> dict:
    info = {}
    t0 = time.monotonic()
    with open(dump, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        info["search"], info["control_hits"] = search(mm, km, labdir, lib, bs, md, ctl)
    if no_scan:
        info["recovery"] = {"performed": False, "reason": "--no-scan"}
    else:
        st_ = structure_scan(dump, km["n"])
        pr = prime_scan(dump, km["n"])
        rec = {"performed": True, "structure": st_, "aligned_factor": pr, "proved": False}
        for r_ in (st_, pr):
            if r_.get("found"):
                ok = prove_recovery(km, r_.pop("factor"))
                r_["proved"] = ok
                rec["proved"] = rec["proved"] or ok
        rec["methods_succeeded"] = [m for m, r_ in (("estrutura DER/PEM", st_), ("fator alinhado", pr)) if r_.get("proved")]
        info["recovery"] = rec
    info["search_seconds"] = round(time.monotonic() - t0, 1)
    info["classification"] = classify(info["search"], info["control_hits"], bool(info["recovery"].get("proved")))
    return info


class Interrupted(Exception):
    pass


def _ignore_further_signals():
    """Depois do primeiro sinal, os seguintes são ignorados para que a limpeza (apagar o dump em curso, gravar o
    status) não seja ela mesma interrompida."""
    import signal
    for s_ in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
        signal.signal(s_, signal.SIG_IGN)


def _on_signal(signum, frame):
    _ignore_further_signals()
    raise Interrupted(f"sinal {signum}")


def install_signal_handlers() -> dict:
    """Instala os tratadores e devolve os anteriores (restaurados ao fim de main)."""
    import signal
    prev = {s_: signal.getsignal(s_) for s_ in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT)}
    for s_ in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(s_, _on_signal)
    return prev


def run_captures(out: Path, header: dict, work: Path, gcore: str, a, bs: int, md: int, lock: "Lock") -> dict:
    """Pré-condição: `lock` já obtida pelo chamador (antes de qualquer leitura/escrita do registro)."""
    n_stale = shred_stale_dumps(work)
    if n_stale:
        event(out, f"{n_stale} dump(s) remanescente(s) de execução interrompida apagado(s) com segurança")
    header["status"] = "running"
    res = persist(out, header)
    if res["integrity_problems"]:
        raise SystemExit(f"problemas de integridade em {rel(out)}: {res['integrity_problems']}")
    done = {c["tag"] for c in res["captures"]}
    todo = [c for c in header["plan"] if c["tag"] not in done]
    event(out, f"início: {len(done)}/{len(header['plan'])} concluídas; {len(todo)} pendentes; pid {os.getpid()}")
    print(f"{len(done)}/{len(header['plan'])} capturas já concluídas; {len(todo)} pendentes em {rel(out)}", flush=True)
    keys_cache: dict[int, tuple] = {}
    try:
        for c in todo:
            rep, lib, tag = c["repetition"], c["lib"], c["tag"]
            if rep not in keys_cache:
                labdir, ctldir, created = rep_keys(work, rep, out)
                km, ctl = key_material(labdir), key_material(ctldir)
                keys_cache[rep] = (labdir, km, ctl)
                fp = key_fingerprint(km)
                header.setdefault("lab_keys", {}).setdefault(str(rep), [])
                if fp not in header["lab_keys"][str(rep)]:
                    header["lab_keys"][str(rep)].append(fp)
                event(out, f"repetição {rep}: chave de laboratório {fp} ({'gerada' if created else 'reutilizada'})")
            labdir, km, ctl = keys_cache[rep]
            dump, info = capture(lib, labdir, PROTOCOL_DIR / "message_90B.txt", work, gcore, tag)
            info.update({"tag": tag, "repetition": rep, "lab_key_fingerprint": key_fingerprint(km), "captured_utc": utc()})
            try:
                if dump:
                    info.update(analyze_dump(dump, km, ctl, labdir, lib, bs, md, a.no_scan))
            finally:
                if dump and not a.keep_dump:
                    secure_remove(dump)
            if dump:
                write_json_atomic(out / "captures" / f"{tag}.json", info)
                event(out, f"{tag}: {info['classification']}")
            else:
                info["classification"] = "falha de captura"
                k = len(list((out / "captures").glob(f"{tag}.attempt*.failed.json"))) + 1
                write_json_atomic(out / "captures" / f"{tag}.attempt{k}.failed.json", info)
                event(out, f"{tag}: FALHA de captura (tentativa {k}): {info.get('error', '?')}")
            persist(out, header)
            print(f"{tag}: {info['classification']} ({info.get('dump_bytes', 0) / 1e6:.0f} MB)", flush=True)
        res = assemble(out, header)
        header["status"] = "complete" if not res["pending"] else "incomplete"
    except (KeyboardInterrupt, Interrupted) as e:
        _ignore_further_signals()
        header["status"] = "interrupted"
        event(out, f"interrompida ({e.__class__.__name__}: {e}); retome com --resume {rel(out)}")
        raise SystemExit(f"interrompida; retome com: python paper_repro/scripts/memory_paper.py --resume {rel(out)}")
    except Exception as e:
        header["status"] = "failed"
        event(out, f"erro: {e.__class__.__name__}: {e}")
        raise
    finally:
        header["finished_utc"] = utc()
        res = persist(out, header)
        shred_stale_dumps(work)  # inclusive o dump de uma captura interrompida no meio (gcore/varredura)
        if header["status"] == "complete" and not a.keep_dump:
            secure_remove(work)  # chaves de laboratório só existem enquanto a análise pode ser retomada
            event(out, "concluída; chaves de laboratório e diretório de trabalho apagados com segurança")
    return res


def main(argv=None):
    proto = load_protocol()["memory"]
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--repetitions", type=int, default=proto["repetitions"])
    ap.add_argument("--libs", default=",".join(LIB_ORDER))
    ap.add_argument("--keep-dump", action="store_true")
    ap.add_argument("--no-scan", action="store_true", help="não faz a busca às cegas por fatores de n")
    ap.add_argument("--resume", help="pasta PM-* interrompida: executa só as capturas pendentes")
    ap.add_argument("--discard", help="pasta PM-* interrompida que NÃO será retomada: apaga com segurança suas chaves e dumps")
    a = ap.parse_args(argv)
    if a.discard:
        out = Path(a.discard).resolve()
        work = work_root() / out.name
        if work.exists():
            lk = acquire_lock(work)  # recusa descartar uma análise que está em andamento
            secure_remove(work)
            lk.release()
        if (out / "memory_results.json").exists():
            event(out, "descartada: chaves de laboratório e dumps apagados com segurança; não será retomada")
        print(f"descartada: {rel(out)}")
        return out
    gcore = shutil.which("gcore")
    pre = preflight(gcore)
    if pre.get("probe") != "ok":
        raise SystemExit(f"gcore indisponível ou sem permissão ({pre.get('probe')}). Análise NÃO executada.")
    bs, md = proto["block_bytes"], proto["min_distinct"]
    old = os.umask(0o077)
    lock = None
    prev_handlers = {}
    try:
        prev_handlers = install_signal_handlers()
        if a.resume:
            out = Path(a.resume).resolve()
            work = work_root() / out.name
            work.mkdir(parents=True, exist_ok=True)
            lock = acquire_lock(work)  # antes de ler o registro: duas retomadas simultâneas -> só uma prossegue
            hf = out / "memory_results.json"
            if not hf.exists():
                raise SystemExit(f"{rel(out)} não tem memory_results.json: não é retomável (execução anterior à "
                                 "persistência incremental); faça uma nova análise")
            header = {k: v for k, v in json.loads(hf.read_text()).items()
                      if k not in ("captures", "failed_attempts", "pending", "integrity_problems", "progress")}
            if header["status"] == "complete":
                raise SystemExit("análise já completa")
            if header.get("method_version") != METHOD_VERSION:
                raise SystemExit(f"método v{header.get('method_version')} != v{METHOD_VERSION} atual: retomada recusada")
            if impl_versions() != header["implementations"]:
                raise SystemExit("versões das implementações mudaram desde o início: retomada recusada")
            header.setdefault("resumes", []).append(utc())
            a.no_scan, a.keep_dump = header.get("no_scan", False), header.get("keep_dump", False)  # mesmo procedimento
            event(out, "retomada solicitada")
        else:
            libs = a.libs.split(",")
            bad = [x for x in libs if x not in LIB_ORDER]
            if bad:
                raise SystemExit(f"bibliotecas desconhecidas: {bad}")
            run_id = f"PM-{utc()}"
            out = mem_dir() / run_id
            out.mkdir(parents=True)  # atômico: duas execuções no mesmo segundo -> a segunda falha aqui, sem gravar nada
            work = work_root() / out.name
            work.mkdir(parents=True, exist_ok=True)
            lock = acquire_lock(work)
            header = {"run_id": run_id, "method_version": METHOD_VERSION, "persistence_version": 2, "created_utc": utc(),
                      "status": "created", "repetitions": a.repetitions, "libraries": libs,
                      "plan": plan_captures(libs, a.repetitions), "block_bytes": bs, "min_distinct": md,
                      "small_block_bytes": SMALL_BLOCK, "preflight": pre, "environment": environment(),
                      "implementations": impl_versions(), "message": "protocol/message_90B.txt",
                      "keep_dump": a.keep_dump, "no_scan": a.no_scan, "resumes": [],
                      # proveniência: o que exatamente produziu as capturas
                      "provenance": provenance()}
            event(out, f"criada: {len(header['plan'])} capturas planejadas")
        (out / "captures").mkdir(exist_ok=True)
        run_captures(out, header, work, gcore, a, bs, md, lock)
    finally:
        os.umask(old)
        if lock is not None:
            lock.release()
        import signal
        for s_, h in prev_handlers.items():
            signal.signal(s_, h)
    print(rel(out / "report.md"))
    return out


if __name__ == "__main__":
    main()
