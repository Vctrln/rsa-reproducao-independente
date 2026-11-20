import sys
from pathlib import Path

import pytest

PAPER = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PAPER / "scripts"))
sys.path.insert(0, str(PAPER / "tools"))

import keys  # noqa: E402
from paper_common import BUILD, LIB_ORDER  # noqa: E402

BITS = [2048, 3072, 4096]


@pytest.fixture(scope="session")
def keydir(tmp_path_factory):
    """Chaves de teste geradas pelo mesmo caminho da coleta (openssl genpkey + conversões)."""
    d = tmp_path_factory.mktemp("paper-keys")
    keys.make_keyset(d, BITS)
    return d


@pytest.fixture(scope="session", autouse=True)
def built():
    missing = [p for p in [BUILD / "c_openssl", BUILD / "c_libgcrypt", BUILD / "cpp_botan", BUILD / "cpp_cryptopp",
                           BUILD / "java" / ".stamp", BUILD / "rust" / ".stamp"] if not p.exists()]
    if missing:
        pytest.exit(f"implementações não compiladas ({', '.join(map(str, missing))}); rode `make paper-build`", 2)
