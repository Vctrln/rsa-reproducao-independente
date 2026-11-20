"""Persistência incremental, interrupção e retomada da análise de memória (memory_paper.py).

DADOS DE TESTE: tudo aqui grava em diretórios temporários (PAPER_RESULTS_ROOT, PAPER_MEMWORK); nenhuma captura
destes testes é resultado científico nem vai para results/. As capturas são reais (gcore) e usam bibliotecas de
dump pequeno, para validar o mecanismo.
"""
import json
import os
import signal
import subprocess
import sys
import time

import pytest

import memory_paper as M
from paper_common import LIB_ORDER, ROOT, load_protocol

LIBS = "c_openssl,rust_rustcrypto,c_libgcrypt"  # dumps de 1–2 MB
pytestmark = pytest.mark.skipif(not __import__("shutil").which("gcore"), reason="gcore indisponível")


@pytest.fixture()
def roots(tmp_path, monkeypatch):
    monkeypatch.setenv("PAPER_RESULTS_ROOT", str(tmp_path / "results"))
    monkeypatch.setenv("PAPER_MEMWORK", str(tmp_path / "memwork"))
    return tmp_path


def _res(out):
    return json.loads((out / "memory_results.json").read_text())


def test_incremental_files_and_order(roots):
    out = M.main(["--libs", LIBS, "--repetitions", "2"])
    res = _res(out)
    assert res["status"] == "complete" and res["progress"] == "6/6" and res["persistence_version"] == 2
    assert [c["tag"] for c in res["captures"]] == [c["tag"] for c in res["plan"]]  # ordem do plano, sem duplicatas
    assert [c["tag"] for c in res["plan"]][:4] == ["c_openssl-r1", "rust_rustcrypto-r1", "c_libgcrypt-r1", "rust_rustcrypto-r2"]
    assert len(list((out / "captures").glob("*.json"))) == 6
    assert all(c["control_hits"] == 0 for c in res["captures"])
    fps = {c["repetition"]: c["lab_key_fingerprint"] for c in res["captures"]}
    assert len({c["lab_key_fingerprint"] for c in res["captures"] if c["repetition"] == 1}) == 1 and fps[1] != fps[2]
    log = (out / "events.log").read_text()
    assert "criada: 6 capturas planejadas" in log and "concluída" in log
    assert not (roots / "memwork" / out.name).exists()
    assert not list(out.rglob("*.tmp"))


def _wait_for(path_glob, n, timeout=180):
    t0 = time.monotonic()
    while time.monotonic() - t0 < timeout:
        if len(list(path_glob())) >= n:
            return
        time.sleep(0.2)
    raise AssertionError("tempo esgotado esperando capturas")


def test_hard_kill_then_resume(roots):
    """Simula o encerramento abrupto do WSL (SIGKILL em TODO o grupo de processos, sem `finally`)."""
    env = dict(os.environ)
    p = subprocess.Popen([sys.executable, str(ROOT / "paper_repro" / "scripts" / "memory_paper.py"), "--libs", LIBS,
                          "--repetitions", "2"], env=env, start_new_session=True,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    pm = roots / "results" / "memory"
    _wait_for(lambda: pm.glob("PM-*/captures/*.json"), 2)
    os.killpg(p.pid, signal.SIGKILL)
    p.wait()
    out = next(pm.glob("PM-*"))
    res = _res(out)
    assert res["status"] == "running"  # nada atualizou o status: foi morto
    done = [c["tag"] for c in res["captures"]]
    assert 2 <= len(done) < 6 and res["pending"]
    work = roots / "memwork" / out.name
    assert (work / "lock").exists() and (work / "lab1" / "2048" / "private.pem").exists()
    fp1 = res["captures"][0]["lab_key_fingerprint"]
    before = {f.name: f.read_bytes() for f in (out / "captures").glob("*.json")}

    out2 = M.main(["--resume", str(out)])
    assert out2 == out
    res2 = _res(out)
    assert res2["status"] == "complete" and res2["progress"] == "6/6" and len(res2["resumes"]) == 1
    # capturas já concluídas preservadas byte a byte e não repetidas
    assert {f.name: f.read_bytes() for f in (out / "captures").glob("*.json") if f.name in before} == before
    assert len(list((out / "captures").glob("*.json"))) == 6
    # mesma chave de laboratório na repetição retomada
    assert {c["lab_key_fingerprint"] for c in res2["captures"] if c["repetition"] == 1} == {fp1}
    assert not work.exists()
    assert "retomada solicitada" in (out / "events.log").read_text()


def test_sigterm_marks_interrupted_and_keeps_partial(roots):
    p = subprocess.Popen([sys.executable, str(ROOT / "paper_repro" / "scripts" / "memory_paper.py"), "--libs", LIBS,
                          "--repetitions", "2"], env=dict(os.environ), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    pm = roots / "results" / "memory"
    _wait_for(lambda: pm.glob("PM-*/captures/*.json"), 1)
    p.send_signal(signal.SIGTERM)
    p.wait(timeout=120)
    out = next(pm.glob("PM-*"))
    res = _res(out)
    assert res["status"] == "interrupted" and res["captures"] and res["pending"]
    assert "PARCIAL" in (out / "report.md").read_text()
    work = roots / "memwork" / out.name
    assert not list(work.glob("dump-*"))  # dump da captura em curso apagado
    M.acquire_lock(work).release()  # trava liberada (o arquivo persiste; o flock não)
    M.main(["--resume", str(out)])
    assert _res(out)["status"] == "complete"


def test_failed_capture_is_recorded_and_retried(roots, monkeypatch):
    real = M.capture
    calls = {"n": 0}

    def flaky(lib, *a, **k):
        if lib == "rust_rustcrypto" and calls["n"] == 0:
            calls["n"] += 1
            return None, {"lib": lib, "error": "falha simulada de teste"}
        return real(lib, *a, **k)
    monkeypatch.setattr(M, "capture", flaky)
    out = M.main(["--libs", LIBS, "--repetitions", "1"])
    res = _res(out)
    assert res["status"] == "incomplete" and res["pending"] == ["rust_rustcrypto-r1"]
    assert len(res["failed_attempts"]) == 1 and (out / "captures" / "rust_rustcrypto-r1.attempt1.failed.json").exists()
    assert (roots / "memwork" / out.name / "lab1").exists()  # chaves mantidas para a retomada
    M.main(["--resume", str(out)])
    res = _res(out)
    assert res["status"] == "complete" and res["progress"] == "3/3" and len(res["failed_attempts"]) == 1


def test_duplicate_or_foreign_capture_blocks_resume(roots, monkeypatch):
    real = M.capture

    def stop_after_first(lib, *a, **k):
        if lib != "c_openssl":
            raise KeyboardInterrupt
        return real(lib, *a, **k)
    monkeypatch.setattr(M, "capture", stop_after_first)
    with pytest.raises(SystemExit):
        M.main(["--libs", LIBS, "--repetitions", "1"])
    out = next((roots / "results" / "memory").glob("PM-*"))
    monkeypatch.setattr(M, "capture", real)
    good = out / "captures" / "c_openssl-r1.json"
    data = json.loads(good.read_text())
    data["lib"] = "js_forge"  # registro incoerente com o plano
    (out / "captures" / "rust_rustcrypto-r1.json").write_text(json.dumps(data))
    with pytest.raises(SystemExit, match="integridade"):
        M.main(["--resume", str(out)])
    assert _res(out)["integrity_problems"]


def test_resume_refuses_legacy_dir_without_results(roots):
    d = roots / "results" / "memory" / "PM-20260101T000000Z"
    d.mkdir(parents=True)
    with pytest.raises(SystemExit, match="não é retomável"):
        M.main(["--resume", str(d)])


def test_resume_refuses_complete_and_discard_shreds(roots):
    out = M.main(["--libs", "c_openssl", "--repetitions", "1"])
    with pytest.raises(SystemExit, match="já completa"):
        M.main(["--resume", str(out)])
    work = roots / "memwork" / "PM-x"
    (work / "lab1").mkdir(parents=True)
    (work / "lab1" / "k").write_bytes(b"segredo")
    M.main(["--discard", str(roots / "results" / "memory" / "PM-x")])
    assert not work.exists()


# ------------------------------------------------------------------ trava atômica, sinais durante a captura
LOCK_SCRIPT = """
import sys, time
sys.path.insert(0, sys.argv[1])
import memory_paper as M
from pathlib import Path
try:
    lk = M.acquire_lock(Path(sys.argv[2]))
except SystemExit:
    print("RECUSADA"); sys.exit(0)
print("OBTIDA", flush=True)
time.sleep(3)
lk.release()
"""


def test_lock_is_atomic_under_concurrency(tmp_path):
    """8 processos disputam a mesma trava ao mesmo tempo: exatamente 1 a obtém."""
    work = tmp_path / "w"
    work.mkdir()
    scripts = str(ROOT / "paper_repro" / "scripts")
    procs = [subprocess.Popen([sys.executable, "-c", LOCK_SCRIPT, scripts, str(work)], stdout=subprocess.PIPE, text=True)
             for _ in range(8)]
    outs = [p.communicate(timeout=60)[0].strip() for p in procs]
    assert outs.count("OBTIDA") == 1 and outs.count("RECUSADA") == 7


def test_lock_released_when_holder_is_killed(tmp_path):
    work = tmp_path / "w"
    work.mkdir()
    p = subprocess.Popen([sys.executable, "-c", LOCK_SCRIPT, str(ROOT / "paper_repro" / "scripts"), str(work)],
                         stdout=subprocess.PIPE, text=True)
    assert p.stdout.readline().strip() == "OBTIDA"
    with pytest.raises(SystemExit, match="já está usando"):
        M.acquire_lock(work)
    p.kill()
    p.wait()
    M.acquire_lock(work).release()  # sem trava "órfã": o kernel a liberou com o SIGKILL


def _interrupted_run(monkeypatch):
    real = M.capture

    def stop_after_first(lib, *a, **k):
        if lib != "c_openssl":
            raise KeyboardInterrupt
        return real(lib, *a, **k)
    monkeypatch.setattr(M, "capture", stop_after_first)
    with pytest.raises(SystemExit):
        M.main(["--libs", LIBS, "--repetitions", "1"])
    monkeypatch.setattr(M, "capture", real)


def test_two_simultaneous_resumes_only_one_proceeds(roots, monkeypatch):
    _interrupted_run(monkeypatch)
    out = next((roots / "results" / "memory").glob("PM-*"))
    cmd = [sys.executable, str(ROOT / "paper_repro" / "scripts" / "memory_paper.py"), "--resume", str(out)]
    ps = [subprocess.Popen(cmd, env=dict(os.environ), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
          for _ in range(2)]
    res = [p.communicate(timeout=300) for p in ps]
    refused = [r for r in res if "já está usando" in r[1]]
    assert len(refused) == 1, res
    final = _res(out)
    assert final["status"] == "complete" and final["progress"] == "3/3" and len(final["resumes"]) == 1
    assert (out / "events.log").read_text().count("retomada solicitada") == 1
    assert len(list((out / "captures").glob("*.json"))) == 3


def test_signal_during_gcore_cleans_dump_and_process(roots, monkeypatch):
    """O sinal chega DENTRO de capture(), depois de o gcore gravar o dump e antes de o controle voltar."""
    import signal
    before = signal.getsignal(signal.SIGTERM)
    real_run = M.subprocess.run

    def run_then_signal(cmd, *a, **k):
        r = real_run(cmd, *a, **k)
        if cmd and str(cmd[0]).endswith("gcore") and str(roots / "memwork") in " ".join(map(str, cmd)):  # não o preflight
            assert list((roots / "memwork").rglob("dump-*"))  # o dump existe neste instante
            M._on_signal(signal.SIGTERM, None)
        return r
    monkeypatch.setattr(M.subprocess, "run", run_then_signal)
    with pytest.raises(SystemExit, match="interrompida"):
        M.main(["--libs", "c_openssl", "--repetitions", "1"])
    out = next((roots / "results" / "memory").glob("PM-*"))
    assert _res(out)["status"] == "interrupted" and not _res(out)["captures"]
    assert not list((roots / "memwork").rglob("dump-*"))  # dump parcial apagado com segurança
    left = subprocess.run(["pgrep", "-f", str(roots / "memwork")], capture_output=True, text=True).stdout
    assert left.strip() == ""  # processo `hold` encerrado
    assert signal.getsignal(signal.SIGTERM) == before  # tratadores restaurados ao sair de main


def test_further_signals_ignored_during_cleanup():
    import signal
    prev = {s_: signal.getsignal(s_) for s_ in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT)}
    try:
        with pytest.raises(M.Interrupted):
            M._on_signal(signal.SIGTERM, None)
        assert all(signal.getsignal(s_) == signal.SIG_IGN for s_ in prev)
    finally:
        for s_, h in prev.items():
            signal.signal(s_, h)


# ------------------------------------------------------------------ validação exata no relatório (DADOS DE TESTE)
