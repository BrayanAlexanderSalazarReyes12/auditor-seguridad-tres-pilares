"""generar_threat_dragon.py — Exporta la evidencia del auditor a Threat Dragon.

Lee el mismo JSON de evidencia que ya produce ``auditor_tramitia.py``
(el que consume ``generar_informe_evidencia.py`` para el DOCX) y arma un
modelo importable en OWASP Threat Dragon v2 (threatdragon.org), con un
proceso por pilar y una amenaza STRIDE por cada hallazgo CONFIRMADO.

No toca el motor del auditor ni el generador de informes: es un script
independiente, del mismo estilo que generar_informe_evidencia.py.

Uso:
    python generar_threat_dragon.py evidencia_B.json -o modelo_threat_dragon.json

Requisitos: solo la libreria estandar (json, hashlib, uuid, argparse).
"""

from __future__ import annotations

import argparse
import json
import uuid
from pathlib import Path
from typing import Any

PILARES = {
    1: {
        "nombre": "Pilar 1 - Identidad y Control de Acceso",
        "activo": "Confidencialidad e integridad de solicitudes y funciones administrativas",
        "frontera": "Identidad real del solicitante vs. identidad de servicio/coordinador",
        "stride": "Elevation of privilege",
        "x": 40,
    },
    2: {
        "nombre": "Pilar 2 - Arquitectura y Configuracion",
        "activo": "Disponibilidad y presupuesto de invocaciones del agente",
        "frontera": "Campo 'urgente' / cabeceras del cliente vs. logica de cuota del servidor",
        "stride": "Denial of service",
        "x": 400,
    },
    3: {
        "nombre": "Pilar 3 - Integridad y Cadena de Suministro",
        "activo": "Integridad del registro de auditoria y de las dependencias",
        "frontera": "Proceso de escritura/instalacion vs. sistema de archivos y repositorios externos",
        "stride": "Tampering",
        "x": 760,
    },
}

SEVERIDAD_TD = {"CRITICA": "Critical", "ALTA": "High", "MEDIA": "Medium", "BAJA": "Low"}


def uid():
    return str(uuid.uuid4())


def nodo_actor(nombre, x, y):
    return {
        "position": {"x": x, "y": y}, "size": {"width": 160, "height": 80},
        "attrs": {"text": {"text": nombre}, "body": {"stroke": "#333333", "strokeWidth": 1}},
        "shape": "actor", "zIndex": 5, "id": uid(),
        "data": {
            "name": nombre, "description": "", "type": "tm.Actor",
            "isTrustBoundary": False, "outOfScope": False, "reasonOutOfScope": "",
            "threats": [], "hasOpenThreats": False, "providesAuthentication": False,
        },
    }


def nodo_proceso(nombre, x, y, amenazas):
    return {
        "position": {"x": x, "y": y}, "size": {"width": 220, "height": 110},
        "attrs": {"text": {"text": nombre}, "body": {"stroke": "red" if amenazas else "#333333", "strokeWidth": 3 if amenazas else 1}},
        "shape": "process", "zIndex": 5, "id": uid(),
        "data": {
            "name": nombre, "description": "", "type": "tm.Process",
            "isTrustBoundary": False, "outOfScope": False, "reasonOutOfScope": "",
            "threats": amenazas, "hasOpenThreats": bool(amenazas),
        },
    }


def limite_confianza(nombre, descripcion, x, y):
    return {
        "shape": "trust-boundary-curve",
        "attrs": {"line": {"targetMarker": "", "sourceMarker": ""}},
        "width": 200, "height": 100, "zIndex": 1, "connector": "smooth",
        "labels": [{"attrs": {"text": {"text": nombre}}}],
        "data": {
            "type": "tm.Boundary", "name": nombre, "description": descripcion,
            "isTrustBoundary": True, "hasOpenThreats": False,
        },
        "id": uid(),
        "source": {"x": x, "y": y}, "target": {"x": x + 260, "y": y}, "vertices": [],
    }


def amenaza_desde_hallazgo(h, stride_tipo):
    return {
        "status": "Open",
        "severity": SEVERIDAD_TD.get(str(h.get("severidad", "")).upper(), "Medium"),
        "title": f"{h.get('regla_id', '?')} - {h.get('hallazgo', 'Hallazgo sin titulo')}",
        "type": stride_tipo,
        "description": str(h.get("detalle") or h.get("categoria_owasp") or ""),
        "mitigation": f"Ver categoria OWASP: {h.get('categoria_owasp', 'no especificada')}. Endpoint/archivo: {h.get('endpoint') or h.get('archivo') or 'n/d'}.",
        "modelType": "STRIDE",
        "id": uid(),
    }


def construir_modelo(evidencia, titulo):
    hallazgos = evidencia.get("hallazgos", [])

    cells = [nodo_actor("Analista autenticado", 40, 260)]

    for pilar_num, meta in PILARES.items():
        confirmados = [
            h for h in hallazgos
            if int(h.get("pilar", -1)) == pilar_num
            and str(h.get("severidad", "")).upper() in {"CRITICA", "ALTA", "MEDIA", "BAJA"}
        ]
        amenazas = [amenaza_desde_hallazgo(h, meta["stride"]) for h in confirmados]
        cells.append(nodo_proceso(meta["nombre"], meta["x"], 60, amenazas))
        cells.append(limite_confianza(
            "Limite " + meta["nombre"].split("-")[0].strip() + ": " + meta["frontera"],
            meta["frontera"], meta["x"] - 20, 200,
        ))

    corrida = evidencia.get("corrida", {})
    resumen = evidencia.get("resumen", {})

    return {
        "summary": {
            "title": titulo,
            "owner": "Diego Andres Garcia Alvarez, Angel Danilo Marin Giraldo, Brayan Alexander Salazar Reyes",
            "description": (
                f"Generado automaticamente desde evidencia_{corrida.get('condicion', '?')}.json "
                f"(corrida_id={corrida.get('corrida_id', 'n/d')}, "
                f"{resumen.get('hallazgos_total', len(hallazgos))} hallazgos totales). "
                "Un proceso por pilar, con una amenaza STRIDE por cada hallazgo confirmado."
            ),
            "id": 0,
        },
        "detail": {
            "contributors": [
                {"name": "Diego Andres Garcia Alvarez"},
                {"name": "Angel Danilo Marin Giraldo"},
                {"name": "Brayan Alexander Salazar Reyes"},
            ],
            "diagrams": [{
                "cells": cells, "version": "2.0", "title": titulo,
                "thumbnail": "./public/content/images/thumbnail.stride.jpg",
                "diagramType": "STRIDE", "id": 0,
            }],
            "diagramTop": 1, "reviewer": "", "threatTop": 0,
        },
        "version": "2.0",
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("evidencia", help="ruta al JSON de evidencia (salida de auditor_tramitia.py)")
    ap.add_argument("-o", "--out", default="modelo_threat_dragon.json")
    ap.add_argument("--titulo", default="Auditor tres pilares - modelo de amenazas")
    args = ap.parse_args()

    datos = json.loads(Path(args.evidencia).read_text(encoding="utf-8"))
    modelo = construir_modelo(datos, args.titulo)

    Path(args.out).write_text(json.dumps(modelo, ensure_ascii=False, indent=2), encoding="utf-8")
    n_amenazas = sum(len(c["data"]["threats"]) for c in modelo["detail"]["diagrams"][0]["cells"] if c.get("shape") == "process" and c["data"].get("threats"))
    print(f"Modelo Threat Dragon escrito en {args.out} ({n_amenazas} amenazas cargadas desde hallazgos confirmados)")


if __name__ == "__main__":
    main()