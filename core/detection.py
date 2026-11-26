"""Clasificación por severidad y categoría mediante reglas simples."""
from collections import defaultdict
from datetime import datetime, timedelta

SURICATA_SEVERITY = {1: "alta", 2: "media", 3: "baja"}
RANK = {"info": 0, "baja": 1, "media": 2, "alta": 3}

# Puerto de destino -> (severidad, categoría)
RISKY_PORTS = {
    23: ("media", "Servicio inseguro: Telnet"),
    2323: ("media", "Servicio inseguro: Telnet alterno"),
    21: ("baja", "Protocolo sin cifrar: FTP"),
    1883: ("baja", "Protocolo IoT sin cifrar: MQTT"),
}

SCAN_PORTS = 10                      # puertos distintos...
SCAN_WINDOW = timedelta(seconds=60)  # ...dentro de esta ventana


def _raise(event, severity, category):
    """Aplica una clasificación solo si es más grave que la actual."""
    if RANK[severity] > RANK[event["severity"]]:
        event["severity"] = severity
        event["category"] = category


def _port_scans(events):
    """Marca cuando un origen contacta muchos puertos de un mismo destino."""
    groups = defaultdict(list)
    for event in events:
        if event["timestamp"] and event["dst_port"] is not None:
            groups[(event["src_ip"], event["dst_ip"])].append(event)

    for group in groups.values():
        group.sort(key=lambda e: e["timestamp"])
        times = [datetime.fromisoformat(e["timestamp"]) for e in group]
        start = 0
        for end in range(len(group)):
            while times[end] - times[start] > SCAN_WINDOW:
                start += 1
            window = group[start:end + 1]
            if len({e["dst_port"] for e in window}) >= SCAN_PORTS:
                for event in window:
                    _raise(event, "media", "Posible escaneo de puertos")


def classify(events):
    """Asigna severity y category a cada evento. Modifica y devuelve la lista."""
    for event in events:
        event["severity"] = "info"
        if event["source"] == "suricata" and event["type"] == "alert":
            level = (event["details"] or {}).get("severity")
            event["severity"] = SURICATA_SEVERITY.get(level, "baja")
            event["category"] = event["category"] or "Alerta de Suricata"
        elif event["source"] == "zeek" and event["type"] == "notice":
            _raise(event, "media", "Aviso de Zeek")

        if event["dst_port"] in RISKY_PORTS:
            _raise(event, *RISKY_PORTS[event["dst_port"]])

    _port_scans(events)

    for event in events:
        event["category"] = event["category"] or "Actividad de red"
    return events
