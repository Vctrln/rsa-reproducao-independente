"""Implementação de referência (pyca/cryptography + aritmética direta) de cada preenchimento do protocolo.

Usada SÓ pelos testes: um texto cifrado por qualquer das 12 bibliotecas tem de ser decifrado aqui com o
preenchimento declarado em protocol.toml, e vice-versa. Assim o teste prova o parâmetro efetivo de cada
biblioteca, não apenas que ela "decifra o que ela mesma cifrou".
"""
from __future__ import annotations

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as P

HASH = {"sha1": hashes.SHA1, "sha256": hashes.SHA256}
HLEN = {"sha1": 20, "sha256": 32}


def max_message(padding: str, k: int) -> int:
    """Maior mensagem aceita (bytes) para módulo de k bytes."""
    if padding.startswith("oaep-"):
        return k - 2 * HLEN[padding.split("-")[1]] - 2
    if padding == "pkcs1v15":
        return k - 11
    if padding == "raw":
        return k - 1  # qualquer m < n; com o 1º byte não nulo, k-1 bytes é sempre < n
    raise ValueError(padding)


def _pad(padding: str):
    if padding.startswith("oaep-"):
        h = HASH[padding.split("-")[1]]
        return P.OAEP(mgf=P.MGF1(algorithm=h()), algorithm=h(), label=None)
    if padding == "pkcs1v15":
        return P.PKCS1v15()
    raise ValueError(padding)


def load(keydir, bits):
    priv = serialization.load_pem_private_key((keydir / str(bits) / "private.pem").read_bytes(), password=None)
    return priv, priv.public_key()


def encrypt(keydir, bits, padding: str, msg: bytes) -> bytes:
    _, pub = load(keydir, bits)
    if padding == "raw":
        n, e = pub.public_numbers().n, pub.public_numbers().e
        return pow(int.from_bytes(msg, "big"), e, n).to_bytes(bits // 8, "big")
    return pub.encrypt(msg, _pad(padding))


def decrypt(keydir, bits, padding: str, ct: bytes) -> bytes:
    priv, pub = load(keydir, bits)
    if padding == "raw":
        nums = priv.private_numbers()
        m = pow(int.from_bytes(ct, "big"), nums.d, nums.public_numbers.n)
        return m.to_bytes((m.bit_length() + 7) // 8, "big")
    return priv.decrypt(ct, _pad(padding))
