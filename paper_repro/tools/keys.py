"""Chaves pré-geradas do protocolo publicado (artigo §3.2) e conversões por biblioteca.

Segundo o artigo (§3.2), as chaves RSA (2048, 3072 e 4096 bits) são pré-geradas com o OpenSSL e carregadas por todas
as implementações. O README dos autores dá os comandos:

    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out private_key.pem
    openssl rsa -in private_key.pem -pubout -out public_key.pem

Formatos derivados (mesma chave):
  private.pem / public.pem   PKCS#8 / SubjectPublicKeyInfo em PEM (a maioria das bibliotecas)
  private.der / public.der   os mesmos em DER (Crypto++, que só carrega DER; artigo §3.2)
  private.sexp / public.sexp S-expressions do Libgcrypt. ADAPTAÇÃO: o artigo usou o pacote monkeysphere (PEM ->
                             GPG) e um script Python não publicado; aqui os parâmetros são extraídos diretamente da
                             chave PKCS#8 (resultado matematicamente equivalente: os mesmos n, e, d, p, q).

Chaves de laboratório: geradas por coleta, nunca reutilizadas fora dela.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path

from cryptography.hazmat.primitives import serialization


def _hex_mpi(v: int) -> str:
    """Inteiro positivo -> hex para S-expression (#..#), com 00 inicial se o bit alto estiver ligado."""
    h = format(v, "x")
    if len(h) % 2:
        h = "0" + h
    if int(h[:2], 16) & 0x80:
        h = "00" + h
    return h.upper()


def gcrypt_sexps(private_pem: bytes) -> tuple[str, str]:
    """S-expressions pública e privada no formato do Libgcrypt (exige p < q e u = p^-1 mod q)."""
    key = serialization.load_pem_private_key(private_pem, password=None)
    nums = key.private_numbers()
    pub = nums.public_numbers
    p, q = sorted((nums.p, nums.q))
    u = pow(p, -1, q)
    pub_s = f"(public-key (rsa (n #{_hex_mpi(pub.n)}#) (e #{_hex_mpi(pub.e)}#)))"
    priv_s = (f"(private-key (rsa (n #{_hex_mpi(pub.n)}#) (e #{_hex_mpi(pub.e)}#) (d #{_hex_mpi(nums.d)}#) "
              f"(p #{_hex_mpi(p)}#) (q #{_hex_mpi(q)}#) (u #{_hex_mpi(u)}#)))")
    return pub_s, priv_s


def openssl_version() -> str:
    return subprocess.run(["openssl", "version"], capture_output=True, text=True, check=True).stdout.strip()


def make_keys(dest: Path, bits: int) -> dict:
    """Gera a chave `bits` com o OpenSSL (comandos do README dos autores) e todos os formatos derivados."""
    d = Path(dest) / str(bits)
    d.mkdir(parents=True, exist_ok=True)
    old = os.umask(0o077)
    try:
        subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", f"rsa_keygen_bits:{bits}",
                        "-out", str(d / "private.pem")], check=True, capture_output=True)
        subprocess.run(["openssl", "rsa", "-in", str(d / "private.pem"), "-pubout", "-out", str(d / "public.pem")],
                       check=True, capture_output=True)
        priv_pem = (d / "private.pem").read_bytes()
        key = serialization.load_pem_private_key(priv_pem, password=None)
        (d / "private.der").write_bytes(key.private_bytes(serialization.Encoding.DER,
                                                          serialization.PrivateFormat.PKCS8,
                                                          serialization.NoEncryption()))
        (d / "public.der").write_bytes(key.public_key().public_bytes(serialization.Encoding.DER,
                                                                     serialization.PublicFormat.SubjectPublicKeyInfo))
        pub_s, priv_s = gcrypt_sexps(priv_pem)
        (d / "public.sexp").write_text(pub_s)
        (d / "private.sexp").write_text(priv_s)
    finally:
        os.umask(old)
    if key.key_size != bits or key.public_key().public_numbers().e != 65537:
        raise RuntimeError(f"chave gerada inesperada: {key.key_size} bits, e={key.public_key().public_numbers().e}")
    files = sorted(p.name for p in d.iterdir())
    return {"bits": bits, "dir": str(d), "public_exponent": 65537,
            "modulus_sha256": hashlib.sha256(key.public_key().public_numbers().n.to_bytes(bits // 8, "big")).hexdigest(),
            "files_sha256": {f: hashlib.sha256((d / f).read_bytes()).hexdigest() for f in files}}


def make_keyset(dest: Path, bits_list) -> dict:
    meta = {"generator": "openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:<B>; openssl rsa -pubout",
            "openssl": openssl_version(), "keys": [make_keys(dest, b) for b in bits_list]}
    (Path(dest) / "keys.json").write_text(json.dumps(meta, indent=2))
    return meta


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("dest")
    ap.add_argument("--bits", default="2048,3072,4096")
    a = ap.parse_args()
    print(json.dumps(make_keyset(Path(a.dest), [int(x) for x in a.bits.split(",")]), indent=2))
