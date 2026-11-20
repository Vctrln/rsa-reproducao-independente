"""Cryptography (pyca) — protocolo publicado. Padrão conferido em Python/Cryptography/pytest/Carregar/test_geral.py
dos autores (commit 1b3ffe0), reimplementado de forma independente:
  - chaves: serialization.load_pem_public_key / load_pem_private_key;
  - OAEP(MGF1(SHA-256), SHA-256, label=None) construído DENTRO de cada operação (como nas funções medidas dos autores);
  - geração: rsa.generate_private_key(public_exponent=65537, key_size=bits).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import cryptography  # noqa: E402
from cryptography.hazmat.backends.openssl.backend import backend  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import padding, rsa  # noqa: E402

from harness import die, meta, run  # noqa: E402


class Lib:
    pub = priv = msg = None

    def meta(self, a):
        return meta("py_cryptography", "Cryptography", f"{cryptography.__version__} ({backend.openssl_version_text()})",
                    "oaep-sha256")

    def load(self, a):
        if a["padding"] not in (None, "oaep-sha256"):
            die(2, "Cryptography: só oaep-sha256 (código dos autores)")
        self.pub = serialization.load_pem_public_key(a["key"]("public.pem").read_bytes())
        self.priv = serialization.load_pem_private_key(a["key"]("private.pem").read_bytes(), password=None)
        # estruturas de chave da biblioteca (comparáveis à Tabela 3 do artigo)
        assert isinstance(self.pub, rsa.RSAPublicKey) and isinstance(self.priv, rsa.RSAPrivateKey)

    def prepare(self, m):
        self.msg = m

    def enc(self):
        return self.pub.encrypt(self.msg, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                       algorithm=hashes.SHA256(), label=None))

    def dec(self, c):
        return self.priv.decrypt(c, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                 algorithm=hashes.SHA256(), label=None))

    cipher_bytes = cipher_from_bytes = plain_bytes = staticmethod(lambda x: x)

    def keygen(self, bits):
        return rsa.generate_private_key(public_exponent=65537, key_size=bits)

    @staticmethod
    def keyinfo(k):
        return k.public_key().public_numbers().e, k.key_size


if __name__ == "__main__":
    run(Lib(), sys.argv[1:])
