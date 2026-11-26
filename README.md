# Proyecto IoT Security

## Probar el motor de eventos
Requiere Python 3.11 o superior. El motor no necesita librerías externas.

    python main.py
    python -m unittest discover -s tests -t .

Con logs reales:

    python main.py ruta/eve.json --casos ruta/casos.csv --salida events.json

## Uso desde el dashboard (integrante 4)

    from core import process
    from core.metrics import summarize
    events, errors = process("data/sample/eve.json")

Cada evento es un diccionario:

| Campo | Contenido |
|---|---|
| id | Identificador de 12 caracteres |
| timestamp | ISO 8601 en UTC (puede ser None) |
| source | suricata o zeek |
| type | alert, flow, dns, http, conn, notice, etc. |
| src_ip, src_port | Origen (pueden ser None) |
| dst_ip, dst_port | Destino (pueden ser None) |
| protocol | TCP, UDP, etc. (puede ser None) |
| signature | Nombre de la alerta (puede ser None) |
| category | Categoría asignada |
| severity | alta, media, baja o info |
| details | Datos originales de la sección del evento |

Antes de enviar un evento a la IA, revisar `details`: puede contener dominios, URLs u otros datos sensibles.

## Matriz de pruebas (Luis y César)
Usar `data/sample/casos.csv` como plantilla. Anotar la hora de inicio y fin de cada
prueba con zona horaria (-04:00). `esperado` es `si` o `no`.

`segundos_hasta_evento` mide desde la hora anotada hasta el primer evento registrado;
no es la latencia interna de Suricata.

## Reglas
- Los datos de `data/sample/` son sintéticos: no son resultados del proyecto.
- No subir logs reales, claves ni datos personales.
