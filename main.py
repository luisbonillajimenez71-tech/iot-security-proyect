"""Prueba el motor desde la terminal.

    python main.py
    python main.py ruta/eve.json --casos ruta/casos.csv --salida events.json
"""
import argparse
import json

from core import process
from core.metrics import evaluate, load_cases, summarize


def main():
    parser = argparse.ArgumentParser(description="Motor de eventos IoT")
    parser.add_argument("logs", nargs="*")
    parser.add_argument("--casos", help="matriz de pruebas en CSV")
    parser.add_argument("--salida", help="guardar eventos normalizados en JSON")
    args = parser.parse_args()

    logs = args.logs or ["data/sample/eve.json", "data/sample/zeek_conn.json"]
    cases = args.casos or (None if args.logs else "data/sample/casos.csv")

    events, errors = process(*logs)
    report = {"resumen": summarize(events), "avisos": errors}
    if cases:
        report["metricas"] = evaluate(events, load_cases(cases))
    print(json.dumps(report, indent=2, ensure_ascii=False))

    if args.salida:
        with open(args.salida, "w", encoding="utf-8") as handle:
            json.dump(events, handle, indent=2, ensure_ascii=False)


if __name__ == "__main__":
    main()
