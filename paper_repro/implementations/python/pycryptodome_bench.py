"""PyCryptodome — protocolo publicado. Padrão conferido em Python/Pycrypto/pytest/Carregar/test_pycryto_geral.py dos
autores (commit 1b3ffe0), reimplementado de forma independente:
  - chaves: RSA.import_key do PEM;
  - PKCS1_OAEP.new(chave) criado UMA vez, fora da operação medida; hash padrão do PKCS1_OAEP = SHA-1 (MGF1-SHA-1);
  - geração: RSA.generate(bits) (e = 65537, padrão).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import Crypto  # noqa: E402
from Crypto.Cipher import PKCS1_OAEP  # noqa: E402
from Crypto.PublicKey import RSA  # noqa: E402

from harness import die, meta, run  # noqa: E402


class Lib:
    enc_cipher = dec_cipher = msg = None

    def meta(self, a):
        return meta("py_pycryptodome", "PyCryptodome", Crypto.__version__, "oaep-sha1")

    def load(self, a):
        if a["padding"] not in (None, "oaep-sha1"):
            die(2, "PyCryptodome: só oaep-sha1 (PKCS1_OAEP padrão)")
        pub = RSA.import_key(a["key"]("public.pem").read_bytes())
        priv = RSA.import_key(a["key"]("private.pem").read_bytes())
        assert isinstance(pub, RSA.RsaKey) and isinstance(priv, RSA.RsaKey)  # estrutura de chave da biblioteca (ver Tabela 3 do artigo)
        self.enc_cipher = PKCS1_OAEP.new(pub)
        self.dec_cipher = PKCS1_OAEP.new(priv)

    def prepare(self, m):
        self.msg = m

    def enc(self):
        return self.enc_cipher.encrypt(self.msg)

    def dec(self, c):
        return self.dec_cipher.decrypt(c)

    cipher_bytes = cipher_from_bytes = plain_bytes = staticmethod(lambda x: x)

    def keygen(self, bits):
        return RSA.generate(bits)

    @staticmethod
    def keyinfo(k):
        return k.e, k.size_in_bits()


if __name__ == "__main__":
    run(Lib(), sys.argv[1:])
