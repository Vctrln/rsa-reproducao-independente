"""Testes do experimento de memória (memory_paper.py): método de busca, layouts, varredura às cegas, classificação,
e uma captura real com gcore (se disponível) gravando só em diretório temporário."""
import json
import mmap
import os
import random
import shutil

import pytest

import memory_paper as M
from paper_common import PROTOCOL_DIR


def test_multi_find_equals_find(tmp_path):
    rng = random.Random(7)
    data = bytearray(rng.randbytes(3_000_000))
    pats = [rng.randbytes(rng.choice([16, 64, 128])) for _ in range(60)]
    for i, p in enumerate(pats[:30]):  # metade plantada, inclusive cruzando a fronteira de bloco (16 MiB não; 1 MiB sim)
        pos = rng.randrange(0, len(data) - len(p))
        data[pos:pos + len(p)] = p
    f = tmp_path / "d.bin"
    f.write_bytes(bytes(data))
    with open(f, "rb") as fh, mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        got = M.multi_find(mm, pats, chunk=1 << 20)
        assert set(got) == {i for i, p in enumerate(pats) if mm.find(p) != -1}
        assert all(mm[o:o + len(pats[i])] == pats[i] for i, offs in got.items() for o in offs)
        assert set(range(30)) <= set(got)


def test_multi_find_pattern_across_chunk_boundary(tmp_path):
    data = bytearray(b"\x11" * (2 << 20))
    p = bytes(range(40, 104))
    data[(1 << 20) - 10:(1 << 20) + 54] = p
    f = tmp_path / "d.bin"
    f.write_bytes(bytes(data))
    with open(f, "rb") as fh, mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        assert M.multi_find(mm, [p], chunk=1 << 20) == {0: [(1 << 20) - 10]}


def test_layouts():
    v = (0x0123456789ABCDEF << 64) | 0x1122334455667788
    be = v.to_bytes(16, "big")
    assert M.java_words(be) == bytes.fromhex("67452301efcdab894433221188776655")
    digits = M.cpython_digits(be)
    assert len(digits) % 4 == 0
    rebuilt = sum(int.from_bytes(digits[i:i + 4], "little") << (30 * (i // 4)) for i in range(0, len(digits), 4))
    assert rebuilt == v


def test_blocks_skip_low_entropy():
    assert M.blocks(b"\0" * 32 + bytes(range(16)), 16, 6) == [bytes(range(16))]


@pytest.fixture(scope="module")
def km(tmp_path_factory):
    import keys
    d = tmp_path_factory.mktemp("memkeys")
    keys.make_keyset(d, [2048])
    return M.key_material(d / "2048"), d / "2048"


@pytest.mark.parametrize("order", ["big", "little"])
def test_prime_scan_finds_planted_factor_blind(tmp_path, km, order):
    k, _ = km
    p = k["key"].private_numbers().p
    rng = random.Random(1)
    filler = bytearray()
    for _ in range(20000):  # mistura de "ponteiros" (com zeros) e texto, como num dump real
        filler += (0x7F0000000000 + rng.randrange(1 << 30)).to_bytes(8, "little") + b"abcdefgh"
    filler += rng.randbytes(4096)  # região aleatória que gera candidatos falsos
    off = len(filler) - len(filler) % 8
    data = bytes(filler[:off]) + p.to_bytes(128, order) + b"\0" * 64
    f = tmp_path / "dump.bin"
    f.write_bytes(data)
    r = M.prime_scan(f, k["n"])
    assert r["found"] and r["offset"] == off and r["byte_order"] == order and r["candidates_tested"] > 1
    assert M.prove_recovery(k, r["factor"])


@pytest.mark.parametrize("form", ["der", "pem"])
def test_structure_scan_recovers_blind(tmp_path, km, form):
    k, keydir = km
    blob = (keydir / "private.der").read_bytes() if form == "der" else (keydir / "private.pem").read_bytes()
    noise = random.Random(4).randbytes(50_000)
    decoy = b"\x30\x82\x04\xbd\x02\x01\x00" + b"\x00" * 1200  # estrutura falsa: deve ser descartada
    f = tmp_path / "dump.bin"
    f.write_bytes(noise + decoy + noise[:777] + blob + noise)
    r = M.structure_scan(f, k["n"], chunk=1 << 15)
    assert r["found"] and r["method"].startswith(form.upper())
    assert M.prove_recovery(k, r["factor"])


def test_prime_scan_absent(tmp_path, km):
    k, _ = km
    f = tmp_path / "dump.bin"
    f.write_bytes(random.Random(2).randbytes(200_000))
    assert M.prime_scan(f, k["n"])["found"] is False


def test_search_and_classify_synthetic(tmp_path, km):
    k, keydir = km
    import keys
    keys.make_keyset(tmp_path / "ctl", [2048])
    ctl = M.key_material(tmp_path / "ctl" / "2048")
    filler = random.Random(3).randbytes(100_000)
    data = filler + k["comps"]["d"][::-1] + filler + b"\n".join(k["pem_lines"][:5]) + filler
    f = tmp_path / "dump.bin"
    f.write_bytes(data)
    with open(f, "rb") as fh, mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        res, ctl_hits = M.search(mm, k, keydir, "c_openssl", 16, 6, ctl)
    assert ctl_hits == 0
    assert res["D_components"]["d"]["full_le"] and not res["D_components"]["d"]["full_be"]
    assert res["A_pem_lines"]["found"] == 5
    assert not res["C_pkcs8_der"]["full"] and not res["E_published_script_public_key"]["full"]
    assert M.classify(res, 0, False) == "material secreto completo presente"
    assert M.classify(res, 1, False).startswith("inconclusivo")
    assert M.classify(res, 0, True) == "chave recuperada sem conhecimento prévio"


def test_secure_remove(tmp_path):
    d = tmp_path / "w"
    d.mkdir()
    (d / "a").write_bytes(b"segredo" * 1000)
    M.secure_remove(d)
    assert not d.exists()


@pytest.mark.skipif(not shutil.which("gcore"), reason="gcore indisponível")
def test_real_capture_two_libraries(tmp_path, monkeypatch):
    """Captura real (c_openssl e py_cryptography) gravando em diretório temporário; confere integridade do registro."""
    monkeypatch.setenv("PAPER_RESULTS_ROOT", str(tmp_path / "results"))
    monkeypatch.setenv("PAPER_MEMWORK", str(tmp_path / "memwork"))
    out = M.main(["--libs", "c_openssl,py_cryptography", "--repetitions", "1"])
    res = json.loads((out / "memory_results.json").read_text())
    assert res["status"] == "complete" and len(res["captures"]) == 2 and res["pending"] == []
    assert sorted(p.name for p in (out / "captures").iterdir()) == ["c_openssl-r1.json", "py_cryptography-r1.json"]
    assert not (tmp_path / "memwork" / out.name).exists()  # chaves e dumps apagados com segurança ao concluir
    for c in res["captures"]:
        assert c["decrypted_ok"] and c["alive_before"] and c["alive_after"] and c["exit_code"] == 0
        assert c["control_hits"] == 0
        assert c["classification"] != "falha de captura"
    text = (out / "report.md").read_text()
    assert "c_openssl" in text and "py_cryptography" in text
    # nenhum material de chave gravado nos resultados
    assert "PRIVATE KEY" not in (out / "memory_results.json").read_text()
    assert PROTOCOL_DIR.exists() and os.access(out, os.R_OK)


def test_control_ignores_shared_asn1_structure(tmp_path, km):
    """Regressão: com DER de mesmo comprimento, os blocos dos offsets 0 e 16 são idênticos nas duas chaves
    (estrutura ASN.1). Eles não podem contar como acerto no controle nem como segredo."""
    import keys
    k, keydir = km
    for i in range(40):
        keys.make_keyset(tmp_path / f"c{i}", [2048])
        ctl = M.key_material(tmp_path / f"c{i}" / "2048")
        if len(ctl["der"]) == len(k["der"]):
            break
    else:
        pytest.skip("não surgiu chave de controle com DER do mesmo comprimento")
    assert ctl["der"][:32] == k["der"][:32]  # a premissa do bug
    f = tmp_path / "dump.bin"
    f.write_bytes(random.Random(5).randbytes(10_000) + k["der"] + (keydir / "private.pem").read_bytes())
    with open(f, "rb") as fh, mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        res, ctl_hits = M.search(mm, k, keydir, "c_openssl", 16, 6, ctl)
    assert ctl_hits == 0
    assert res["C_pkcs8_der"]["full"] and res["C_pkcs8_der"]["blocks_found"] == res["C_pkcs8_der"]["blocks_total"]
    assert res["C_pkcs8_der"]["blocks_total"] <= len(k["der"]) // 16 - 2


def test_longest_contiguous():
    assert M.longest_contiguous([[100], [116], [132], None, [500]], 16) == 3
    assert M.longest_contiguous([[200], [184], [168]], -16) == 3
    assert M.longest_contiguous([[0, 300], [316], [999]], 16) == 2
    assert M.longest_contiguous([None, None], 16) == 0


def test_contiguity_and_small_blocks_in_search(tmp_path, km):
    k, keydir = km
    import keys
    keys.make_keyset(tmp_path / "ctl", [2048])
    ctl = M.key_material(tmp_path / "ctl" / "2048")
    der = k["der"]
    noise = random.Random(9).randbytes(20_000)
    # DER inteiro invertido (como limbs little-endian) + metade do DER em ordem normal
    data = noise + der[::-1] + noise + der[: len(der) // 2] + noise
    f = tmp_path / "dump.bin"
    f.write_bytes(data)
    with open(f, "rb") as fh, mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        res, ctl_hits = M.search(mm, k, keydir, "c_openssl", 16, 6, ctl)
    c = res["C_pkcs8_der"]
    assert ctl_hits == 0 and c["full_reversed"] and not c["full"]
    assert c["longest_consecutive_blocks_reversed"] == c["blocks_total"]
    assert 0 < c["longest_consecutive_blocks"] < c["blocks_total"]
    assert c["small_block_bytes"] == 8 and c["small_blocks_total"] > c["blocks_total"]
