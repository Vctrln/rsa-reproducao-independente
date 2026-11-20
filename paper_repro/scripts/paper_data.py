"""Leitura e validação estrita da saída `bench` das implementações (formato em implementations/CONTRACT.md).

Usado na coleta (cada unidade é validada antes de ser gravada como completa) e na análise (tudo é revalidado
antes de qualquer cálculo; qualquer falha aborta).
"""
from __future__ import annotations

import json


class InvalidOutput(ValueError):
    pass


def expectations(cfg: dict, u: dict) -> dict:
    """Parâmetros de validação de uma unidade.
    kind = "keygen": experimento independente de geração (sem conjuntos; expoente e tamanho conferidos);
    kind = "encdec": cifração/decifração com as chaves pré-geradas (sem geração embutida);
    sem kind (coletas anteriores a esta separação): bench com geração embutida."""
    kind = u.get("kind")
    if kind == "keygen":
        return {"sets": [], "keygen_rounds": cfg["keygen_per_execution"],
                "expected_e": cfg["libraries"][u["lib"]]["keygen_e"]}
    if kind == "encdec":
        return {"sets": cfg["iteration_sets"], "keygen_rounds": 0}
    return {"sets": cfg["iteration_sets"], "keygen_rounds": cfg["keygen_per_execution"]}


def parse_bench(text: str, *, lib: str, padding: str, bits: int, sets: list[int], keygen_rounds: int,
                expected_e: int | None = None) -> dict:
    """Valida a saída de `bench` (sets = conjuntos esperados) ou de `keygen` (sets = []).
    Linhas keygen com 6 campos trazem o expoente e o tamanho do módulo GERADOS: conferidos contra
    `expected_e` e `bits`. Coletas antigas (4 campos) continuam legíveis."""
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if not lines or not lines[0].startswith("meta,"):
        raise InvalidOutput("primeira linha não é meta")
    if lines[-1] != "done":
        raise InvalidOutput("saída incompleta (sem 'done')")
    meta = json.loads(lines[0][5:])
    if meta.get("id") != lib:
        raise InvalidOutput(f"id {meta.get('id')!r} != {lib!r}")
    if meta.get("padding") != padding:
        raise InvalidOutput(f"preenchimento {meta.get('padding')!r} != {padding!r}")
    keygen, ops = [], []
    for ln in lines[1:-1]:
        f = ln.split(",")
        if f[0] == "keygen":
            if len(f) not in (4, 6) or int(f[1]) != bits:
                raise InvalidOutput(f"linha keygen inválida: {ln}")
            v = float(f[3])
            if not v > 0:
                raise InvalidOutput("tempo de geração não positivo")
            rec = {"round": int(f[2]), "seconds": v}
            if len(f) == 6:
                rec["public_exponent"], rec["modulus_bits"] = int(f[4]), int(f[5])
                if rec["modulus_bits"] != bits:
                    raise InvalidOutput(f"chave gerada com {rec['modulus_bits']} bits, esperado {bits}")
                if expected_e is not None and rec["public_exponent"] != expected_e:
                    raise InvalidOutput(f"chave gerada com e={rec['public_exponent']}, esperado {expected_e}")
            elif expected_e is not None:
                raise InvalidOutput("linha keygen sem expoente/tamanho gerados")
            keygen.append(rec)
        elif f[0] == "set":
            if len(f) != 9 or f[2] not in ("encrypt", "decrypt"):
                raise InvalidOutput(f"linha set inválida: {ln}")
            n_set, n = int(f[1]), int(f[3])
            mean, sd, mn, mx, total = map(float, f[4:9])
            if n != n_set:
                raise InvalidOutput(f"conjunto {n_set} com {n} medidas")
            if not (0 < mn <= mean * (1 + 1e-9) and mean <= mx * (1 + 1e-9) and sd >= 0):
                raise InvalidOutput(f"estatística incoerente: {ln}")
            if abs(total - mean * n) > 1e-6 * total + 1e-12:
                raise InvalidOutput(f"total != média × n: {ln}")
            ops.append({"set": n_set, "operation": f[2], "n": n, "mean_s": mean, "sd_s": sd, "min_s": mn,
                        "max_s": mx, "total_s": total})
        else:
            raise InvalidOutput(f"linha desconhecida: {ln}")
    if [k["round"] for k in keygen] != list(range(1, keygen_rounds + 1)):
        raise InvalidOutput(f"esperadas {keygen_rounds} gerações de chave, encontradas {len(keygen)}")
    expected = [(s, op) for s in sets for op in ("encrypt", "decrypt")]
    if [(o["set"], o["operation"]) for o in ops] != expected:
        raise InvalidOutput(f"conjuntos {[(o['set'], o['operation']) for o in ops]} != {expected}")
    return {"meta": meta, "keygen": keygen, "ops": ops}
