"""Lectura de logs en formato JSON: Suricata (eve.json) y Zeek (JSON)."""
import json
from pathlib import Path


def read_log(path):
    """Devuelve (registros, errores).

    Acepta un objeto JSON por línea (formato de eve.json y Zeek) o un arreglo JSON.
    Una línea dañada no detiene la lectura: se anota en errores.
    """
    text = Path(path).read_text(encoding="utf-8-sig", errors="replace").strip()
    records, errors = [], []

    if text.startswith("["):
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            return [], [f"JSON inválido: {exc}"]
        for i, item in enumerate(data, 1):
            if isinstance(item, dict):
                records.append(item)
            else:
                errors.append(f"Elemento {i}: no es un objeto JSON")
        return records, errors

    for number, line in enumerate(text.split("\n"), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError as exc:
            errors.append(f"Línea {number}: {exc.msg}")
            continue
        if isinstance(item, dict):
            records.append(item)
        else:
            errors.append(f"Línea {number}: no es un objeto JSON")
    return records, errors
