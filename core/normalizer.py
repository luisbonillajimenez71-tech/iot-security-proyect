"""Convierte registros de Suricata y Zeek al esquema común de eventos."""
import hashlib
import json
from datetime import datetime, timezone

FIELDS = (
    "id", "timestamp", "source", "type", "src_ip", "src_port", "dst_ip",
    "dst_port", "protocol", "signature", "category", "severity", "details",
)


def to_utc(value):
    """Fecha de Suricata (texto ISO) o de Zeek (epoch) a ISO 8601 en UTC."""
    if value in (None, ""):
        return None
    try:
        if isinstance(value, (int, float)):
            moment = datetime.fromtimestamp(value, tz=timezone.utc)
        else:
            moment = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            if moment.tzinfo is None:
                moment = moment.replace(tzinfo=timezone.utc)
        return moment.astimezone(timezone.utc).isoformat()
    except (ValueError, OverflowError, OSError):
        return None


def _port(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _event(raw, **values):
    event = {field: None for field in FIELDS}
    event.update(values)
    canonical = json.dumps(raw, sort_keys=True, default=str)
    event["id"] = hashlib.sha256(canonical.encode()).hexdigest()[:12]
    return event


def _from_suricata(raw):
    kind = raw["event_type"]
    section = raw.get(kind)
    section = section if isinstance(section, dict) else {}
    return _event(
        raw,
        timestamp=to_utc(raw.get("timestamp")),
        source="suricata",
        type=kind,
        src_ip=raw.get("src_ip"),
        src_port=_port(raw.get("src_port")),
        dst_ip=raw.get("dest_ip"),
        dst_port=_port(raw.get("dest_port")),
        protocol=(raw.get("proto") or "").upper() or None,
        signature=section.get("signature") if kind == "alert" else None,
        category=section.get("category") if kind == "alert" else None,
        details={**section},
    )


def _zeek_type(raw):
    if "query" in raw:
        return "dns"
    if "method" in raw or "uri" in raw:
        return "http"
    if "note" in raw:
        return "notice"
    return "conn"


def _from_zeek(raw):
    base = {"ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto"}
    kind = _zeek_type(raw)
    return _event(
        raw,
        timestamp=to_utc(raw.get("ts")),
        source="zeek",
        type=kind,
        src_ip=raw.get("id.orig_h"),
        src_port=_port(raw.get("id.orig_p")),
        dst_ip=raw.get("id.resp_h"),
        dst_port=_port(raw.get("id.resp_p")),
        protocol=(raw.get("proto") or "").upper() or None,
        signature=raw.get("note"),
        details={k: v for k, v in raw.items() if k not in base},
    )


def normalize(raw):
    """Devuelve un evento común, o None si el registro no se reconoce."""
    if isinstance(raw.get("event_type"), str):
        # 'stats' son contadores internos de Suricata, no eventos de red.
        return None if raw["event_type"] == "stats" else _from_suricata(raw)
    if "ts" in raw and "id.orig_h" in raw:
        return _from_zeek(raw)
    return None
