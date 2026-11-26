"""Resumen de eventos y métricas de las pruebas."""
import csv
from collections import Counter
from datetime import datetime
from statistics import mean


def summarize(events):
    return {
        "total": len(events),
        "por_severidad": dict(Counter(e["severity"] for e in events)),
        "por_categoria": dict(Counter(e["category"] for e in events)),
        "por_fuente": dict(Counter(e["source"] for e in events)),
    }


def load_cases(path):
    """Lee la matriz de pruebas (CSV).

    Columnas: case_id, src_ip, dst_ip, inicio, fin, esperado (si/no), descripcion.
    inicio y fin llevan zona horaria, por ejemplo 2026-11-26T10:00:00-04:00.
    """
    with open(path, encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def evaluate(events, cases):
    """Compara cada caso de prueba contra los eventos no informativos."""
    results = []
    for case in cases:
        start = datetime.fromisoformat(case["inicio"])
        end = datetime.fromisoformat(case["fin"])
        hits = sorted(
            datetime.fromisoformat(e["timestamp"])
            for e in events
            if e["severity"] != "info"
            and e["timestamp"]
            and e["src_ip"] == case["src_ip"]
            and e["dst_ip"] == case["dst_ip"]
            and start <= datetime.fromisoformat(e["timestamp"]) <= end
        )
        expected = case["esperado"].strip().lower() in ("si", "sí")
        detected = bool(hits)
        outcome = {(True, True): "VP", (True, False): "FN",
                   (False, True): "FP", (False, False): "VN"}[(expected, detected)]
        results.append({
            "case_id": case["case_id"],
            "descripcion": case.get("descripcion", ""),
            "resultado": outcome,
            # Segundos desde el inicio anotado del caso hasta el primer evento.
            "segundos_hasta_evento": (hits[0] - start).total_seconds() if hits else None,
        })

    count = Counter(r["resultado"] for r in results)
    vp, fn, fp, vn = (count[k] for k in ("VP", "FN", "FP", "VN"))
    delays = [r["segundos_hasta_evento"] for r in results if r["resultado"] == "VP"]

    def ratio(a, b):
        return round(a / b, 4) if b else None

    return {
        "casos": results,
        "VP": vp, "FN": fn, "FP": fp, "VN": vn,
        "tasa_deteccion": ratio(vp, vp + fn),
        "precision": ratio(vp, vp + fp),
        "tasa_falsos_positivos": ratio(fp, fp + vn),
        "segundos_promedio": round(mean(delays), 2) if delays else None,
    }
