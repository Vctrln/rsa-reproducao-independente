"""Testes funcionais das 12 implementações (e da variante Libgcrypt raw) do protocolo publicado.

Não basta compilar: para cada biblioteca e cada chave (2048/3072/4096) verifica-se
  1. o modo `bench` completo (geração, conjuntos, verificação interna, formato da saída);
  2. interoperabilidade com uma referência independente (tools/refcrypto.py) NOS DOIS SENTIDOS, com o
     preenchimento declarado em protocol.toml — prova o parâmetro efetivo, não só o round-trip;
  3. o limite de mensagem do preenchimento (maior mensagem aceita e a primeira recusada);
  4. casos negativos (preenchimento não suportado, texto cifrado adulterado) e o modo `hold` da análise de memória.
"""
import json
import subprocess

import pytest
import refcrypto
from conftest import BITS, LIB_ORDER
from paper_common import PROTOCOL_DIR, impl_argv, resolve

CFG = resolve("full")
PAD = {k: v["padding"] for k, v in CFG["libraries"].items()}
MSG = (PROTOCOL_DIR / "message_90B.txt").read_bytes()
# (id do teste, id da implementação, preenchimento passado em --padding ou None)
CASES = [(lib, lib, None) for lib in LIB_ORDER] + [("c_libgcrypt_raw", "c_libgcrypt", "raw")]


def padding_of(case):
    return case[2] or PAD[case[1]]


def run(case, *args, timeout=600, stdin=None):
    extra = ["--padding", case[2]] if case[2] else []
    return subprocess.run(impl_argv(case[1]) + list(args) + extra, capture_output=True, text=True,
                          timeout=timeout, input=stdin)


def ids(cases):
    return [c[0] for c in cases]


@pytest.mark.parametrize("bits", BITS)
@pytest.mark.parametrize("case", CASES, ids=ids(CASES))
def test_bench_mode(case, bits, keydir):
    r = run(case, "bench", "--keydir", str(keydir), "--bits", str(bits), "--msg", str(PROTOCOL_DIR / "message_90B.txt"),
            "--sets", "3,5", "--keygen-rounds", "1")
    assert r.returncode == 0, r.stderr
    lines = r.stdout.strip().splitlines()
    assert lines[0].startswith("meta,") and lines[-1] == "done"
    meta = json.loads(lines[0][5:])
    assert meta["id"] == case[1] and meta["padding"] == padding_of(case)
    kg = [ln.split(",") for ln in lines if ln.startswith("keygen,")]
    assert len(kg) == 1 and int(kg[0][1]) == bits and float(kg[0][3]) > 0
    sets = [ln.split(",") for ln in lines if ln.startswith("set,")]
    assert [(s[1], s[2], s[3]) for s in sets] == [("3", "encrypt", "3"), ("3", "decrypt", "3"),
                                                  ("5", "encrypt", "5"), ("5", "decrypt", "5")]
    for s in sets:
        mean, sd, mn, mx, total = map(float, s[4:9])
        assert 0 < mn <= mean <= mx and sd >= 0 and abs(total - mean * int(s[3])) <= 1e-9 + 1e-6 * total


@pytest.mark.parametrize("bits", BITS)
@pytest.mark.parametrize("case", CASES, ids=ids(CASES))
def test_interop_library_to_reference(case, bits, keydir):
    r = run(case, "encrypt", "--keydir", str(keydir), "--bits", str(bits), "--msg", str(PROTOCOL_DIR / "message_90B.txt"))
    assert r.returncode == 0, r.stderr
    ct = bytes.fromhex(r.stdout.strip())
    k = bits // 8
    assert len(ct) <= k and (padding_of(case) == "raw" or len(ct) == k)
    assert refcrypto.decrypt(keydir, bits, padding_of(case), ct.rjust(k, b"\0")) == MSG


@pytest.mark.parametrize("bits", BITS)
@pytest.mark.parametrize("case", CASES, ids=ids(CASES))
def test_interop_reference_to_library(case, bits, keydir, tmp_path):
    ct = refcrypto.encrypt(keydir, bits, padding_of(case), MSG)
    f = tmp_path / "ct.hex"
    f.write_text(ct.hex())
    r = run(case, "decrypt", "--keydir", str(keydir), "--bits", str(bits), "--in", str(f))
    assert r.returncode == 0, r.stderr
    assert bytes.fromhex(r.stdout.strip()) == MSG


@pytest.mark.parametrize("bits", BITS)
@pytest.mark.parametrize("case", CASES, ids=ids(CASES))
def test_message_limit(case, bits, keydir, tmp_path):
    """Maior mensagem aceita = limite do preenchimento declarado; um byte a mais é recusado (saída 3)."""
    pad, k = padding_of(case), bits // 8
    limit = refcrypto.max_message(pad, k)
    ok = tmp_path / "ok.txt"
    ok.write_bytes(b"R" + b"x" * (limit - 1))
    r = run(case, "encrypt", "--keydir", str(keydir), "--bits", str(bits), "--msg", str(ok))
    assert r.returncode == 0, r.stderr
    got = refcrypto.decrypt(keydir, bits, pad, bytes.fromhex(r.stdout.strip()).rjust(k, b"\0"))
    assert got == ok.read_bytes()
    over = tmp_path / "over.txt"
    over.write_bytes(b"\x7f" * (limit + (2 if pad == "raw" else 1)))  # raw: k+1 bytes é sempre > n
    r = run(case, "encrypt", "--keydir", str(keydir), "--bits", str(bits), "--msg", str(over))
    if case[0] == "c_libgcrypt_raw":
        # Comportamento documentado do Libgcrypt com (flags raw): valor >= n NÃO é recusado; é reduzido mod n e a
        # decifração devolve m mod n (dado corrompido, sem erro). Relevante para a variante do código dos autores.
        assert r.returncode == 0, r.stderr
        n = refcrypto.load(keydir, bits)[1].public_numbers().n
        got = refcrypto.decrypt(keydir, bits, "raw", bytes.fromhex(r.stdout.strip()).rjust(k, b"\0"))
        assert int.from_bytes(got, "big") == int.from_bytes(over.read_bytes(), "big") % n
        assert got != over.read_bytes()
        return
    assert r.returncode == 3, (r.returncode, r.stdout[:80], r.stderr)


# OpenSSL 3.0.13 do Ubuntu 24.04 aplica a "rejeição implícita" do PKCS#1 v1.5 (mitigação do ataque Marvin):
# um texto cifrado adulterado devolve uma mensagem pseudoaleatória determinística, sem erro. Vale para as
# implementações sobre o OpenSSL do sistema com PKCS#1 v1.5.
IMPLICIT_REJECTION = {"c_openssl", "rust_openssl"}


@pytest.mark.parametrize("case", [c for c in CASES if padding_of(c) != "raw"], ids=ids([c for c in CASES if padding_of(c) != "raw"]))
def test_tampered_ciphertext_is_rejected(case, keydir, tmp_path):
    ct = bytearray(refcrypto.encrypt(keydir, 2048, padding_of(case), MSG))
    ct[-1] ^= 0x01
    f = tmp_path / "bad.hex"
    f.write_text(bytes(ct).hex())
    r = run(case, "decrypt", "--keydir", str(keydir), "--bits", "2048", "--in", str(f))
    if case[1] in IMPLICIT_REJECTION:
        assert r.returncode == 0 and bytes.fromhex(r.stdout.strip()) != MSG
        r2 = run(case, "decrypt", "--keydir", str(keydir), "--bits", "2048", "--in", str(f))
        assert r2.stdout == r.stdout  # determinística (derivada da chave e do texto cifrado)
    else:
        assert r.returncode == 4, (r.returncode, r.stdout, r.stderr)


@pytest.mark.parametrize("lib", LIB_ORDER)
def test_unsupported_padding_is_refused(lib, keydir):
    other = "raw" if PAD[lib] != "raw" else "pkcs1v15"
    r = subprocess.run(impl_argv(lib) + ["encrypt", "--keydir", str(keydir), "--bits", "2048", "--msg",
                                         str(PROTOCOL_DIR / "message_90B.txt"), "--padding", other],
                       capture_output=True, text=True, timeout=120)
    if lib == "c_libgcrypt" and other == "raw":
        assert r.returncode == 0  # a variante raw do Libgcrypt existe de propósito
    else:
        assert r.returncode == 2, (r.returncode, r.stderr)


@pytest.mark.parametrize("case", CASES, ids=ids(CASES))
def test_hold_mode(case, keydir):
    p = subprocess.Popen(impl_argv(case[1]) + ["hold", "--keydir", str(keydir), "--bits", "2048", "--msg",
                                               str(PROTOCOL_DIR / "message_90B.txt")] +
                         (["--padding", case[2]] if case[2] else []),
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    line = p.stdout.readline().strip()
    assert line == "READY " + MSG.hex()
    assert p.poll() is None  # continua vivo com a chave carregada
    p.stdin.write("\n")
    p.stdin.flush()
    assert p.wait(timeout=60) == 0


@pytest.mark.parametrize("lib", LIB_ORDER)
def test_bad_arguments(lib, keydir):
    r = subprocess.run(impl_argv(lib) + ["bench", "--keydir", str(keydir), "--bits", "1024", "--msg", "x", "--sets", "1"],
                       capture_output=True, text=True, timeout=120)
    assert r.returncode == 2



@pytest.mark.parametrize("bits", BITS)
@pytest.mark.parametrize("lib", LIB_ORDER)
def test_keygen_mode(lib, bits):
    """Experimento independente de geração: sem chaves pré-geradas, só a geração da própria biblioteca; a chave
    GERADA tem o tamanho pedido e o expoente esperado (65537; Crypto++ 17, padrão da biblioteca)."""
    r = subprocess.run(impl_argv(lib) + ["keygen", "--bits", str(bits), "--keygen-rounds", "2"],
                       capture_output=True, text=True, timeout=900)
    assert r.returncode == 0, r.stderr
    lines = r.stdout.strip().splitlines()
    assert lines[0].startswith("meta,") and lines[-1] == "done" and len(lines) == 4
    for i, ln in enumerate(lines[1:3], 1):
        f = ln.split(",")
        assert f[0] == "keygen" and int(f[1]) == bits and int(f[2]) == i and float(f[3]) > 0
        assert int(f[4]) == CFG["libraries"][lib]["keygen_e"] and int(f[5]) == bits


@pytest.mark.parametrize("lib", LIB_ORDER)
def test_bench_without_embedded_keygen(lib, keydir):
    r = subprocess.run(impl_argv(lib) + ["bench", "--keydir", str(keydir), "--bits", "2048", "--msg",
                                         str(PROTOCOL_DIR / "message_90B.txt"), "--sets", "2", "--keygen-rounds", "0"],
                       capture_output=True, text=True, timeout=300)
    assert r.returncode == 0, r.stderr
    assert not [ln for ln in r.stdout.splitlines() if ln.startswith("keygen,")]


def test_parse_rejects_wrong_exponent_or_size():
    from paper_data import InvalidOutput, parse_bench
    ok = 'meta,{"id":"x","padding":"raw"}\nkeygen,2048,1,1.0e-1,65537,2048\ndone\n'
    parse_bench(ok, lib="x", padding="raw", bits=2048, sets=[], keygen_rounds=1, expected_e=65537)
    with pytest.raises(InvalidOutput):
        parse_bench(ok.replace(",65537,", ",17,"), lib="x", padding="raw", bits=2048, sets=[], keygen_rounds=1, expected_e=65537)
    with pytest.raises(InvalidOutput):
        parse_bench(ok.replace(",2048\n", ",2047\n"), lib="x", padding="raw", bits=2048, sets=[], keygen_rounds=1)
