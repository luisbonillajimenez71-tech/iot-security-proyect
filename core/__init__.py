"""Punto de entrada del motor de eventos.

    from core import process
    events, errors = process("data/sample/eve.json", "data/sample/zeek_conn.json")
"""
from .detection import classify
from .normalizer import normalize
from .parser import read_log


def process(*paths):
    """Lee uno o varios logs. Devuelve (eventos ordenados por fecha, errores)."""
    events, errors, seen = [], [], set()
    for path in paths:
        records, read_errors = read_log(path)
        errors.extend(f"{path}: {message}" for message in read_errors)
        skipped = 0
        for record in records:
            event = normalize(record)
            if event is None:
                skipped += 1
            elif event["id"] not in seen:  # evita registros repetidos
                seen.add(event["id"])
                events.append(event)
        if skipped:
            errors.append(f"{path}: {skipped} registro(s) omitido(s) (stats o formato desconocido)")
    classify(events)
    events.sort(key=lambda e: e["timestamp"] or "")
    return events, errors
