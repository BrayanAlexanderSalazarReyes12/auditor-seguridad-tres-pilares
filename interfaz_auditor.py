#!/usr/bin/env python3
"""Interfaz web local para el auditor determinista de los tres pilares.

El servidor se enlaza exclusivamente a 127.0.0.1, usa un token aleatorio por
sesión y no persiste las credenciales de laboratorio.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import subprocess
import sys
import threading
import webbrowser
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


APP_DIR = Path(__file__).resolve().parent
WEB_DIR = APP_DIR / "web"
AUDITOR_SCRIPT = APP_DIR / "auditor_tramitia.py"
SELECTOR_SCRIPT = APP_DIR / "selector_archivos.py"
DEFAULT_CONFIG = APP_DIR / "auditor_config.tramitia.example.json"
DEFAULT_RESULTS = APP_DIR / "resultados"
MAX_REQUEST_BYTES = 131_072
MAX_LOG_LINES = 500


@dataclass(frozen=True)
class IdentityCredential:
    label: str
    username: str = ""
    password: str = ""


@dataclass(frozen=True)
class AuditOptions:
    repository: Path
    config: Path
    output_dir: Path
    pillars: tuple[int, ...] = (1, 2, 3)
    base_url: str = "http://127.0.0.1:5050"
    condition: str = "A"
    compare_with: Path | None = None
    generate_docx: bool = True
    authorized: bool = False
    active_tests: bool = False
    allow_network: bool = False
    fail_on: str = ""
    identities: tuple[IdentityCredential, ...] = ()

    @property
    def evidence_path(self) -> Path:
        return self.output_dir / f"evidencia_{self.condition}.json"

    @property
    def report_path(self) -> Path:
        return self.output_dir / f"Informe_Profesional_Ciberseguridad_{self.condition}.docx"


def validate_options(options: AuditOptions) -> list[str]:
    errors: list[str] = []
    if not options.authorized:
        errors.append("Debe confirmar que el repositorio y el entorno están autorizados.")
    if not str(options.repository).strip() or not options.repository.is_dir():
        errors.append("Seleccione una carpeta de repositorio existente.")
    if not str(options.config).strip() or not options.config.is_file():
        errors.append("Seleccione un archivo de configuración JSON existente.")
    if not options.pillars:
        errors.append("Seleccione al menos un pilar.")
    if any(pillar not in {1, 2, 3} for pillar in options.pillars):
        errors.append("Los pilares permitidos son 1, 2 y 3.")
    if options.condition not in {"A", "B"}:
        errors.append("La condición debe ser A o B.")
    if any(pillar in {1, 2} for pillar in options.pillars) and not options.base_url.strip():
        errors.append("La URL base es obligatoria para los pilares 1 y 2.")
    if options.compare_with and not options.compare_with.is_file():
        errors.append("La evidencia de comparación no existe.")
    if options.compare_with and options.compare_with.resolve() == options.evidence_path.resolve():
        errors.append("La evidencia actual y la evidencia de comparación deben ser archivos distintos.")
    if options.active_tests and not any(pillar in {1, 2} for pillar in options.pillars):
        errors.append("Las pruebas activas solo aplican cuando se ejecuta el pilar 1 o 2.")
    if options.fail_on not in {"", "INFORMATIVA", "BAJA", "MEDIA", "ALTA", "CRITICA"}:
        errors.append("El umbral de fallo no es válido.")
    labels = [identity.label.upper() for identity in options.identities]
    if len(labels) > 12 or len(labels) != len(set(labels)):
        errors.append("Las identidades deben ser únicas y no pueden superar 12 usuarios.")
    if any(len(label) != 1 or label < "A" or label > "L" for label in labels):
        errors.append("Cada identidad debe usar una letra entre A y L.")
    return errors


def build_auditor_command(
    options: AuditOptions,
    *,
    python_executable: str | Path = sys.executable,
    script_path: str | Path = AUDITOR_SCRIPT,
) -> list[str]:
    command = [
        str(python_executable), str(script_path), "--repo", str(options.repository),
        "--config", str(options.config), "--pilares",
        ",".join(str(pillar) for pillar in sorted(options.pillars)),
        "--condicion", options.condition, "--out", str(options.evidence_path), "--autorizado",
    ]
    if options.base_url.strip():
        command.extend(["--base-url", options.base_url.strip()])
    if options.generate_docx:
        command.extend(["--out-docx", str(options.report_path)])
    if options.compare_with:
        command.extend(["--comparar-con", str(options.compare_with)])
    if options.active_tests:
        command.append("--permitir-pruebas-activas")
    if options.allow_network:
        command.append("--permitir-red")
    if options.fail_on:
        command.extend(["--fail-on", options.fail_on])
    return command


def build_process_environment(options: AuditOptions, base: dict[str, str] | None = None) -> dict[str, str]:
    environment = dict(base if base is not None else os.environ)
    for identity in options.identities:
        label = identity.label.upper()
        if identity.username:
            environment[f"AUDITOR_TRAMITIA_USER_{label}"] = identity.username
        if identity.password:
            environment[f"AUDITOR_TRAMITIA_PASSWORD_{label}"] = identity.password
    environment["PYTHONUTF8"] = "1"
    return environment


def read_evidence_summary(path: Path) -> dict[str, Any]:
    report = json.loads(path.read_text(encoding="utf-8"))
    summary = report.get("resumen", {})
    states = summary.get("por_estado", {})
    severities = summary.get("por_severidad", {})
    comparison = report.get("comparacion_ab") or {}
    return {
        "condition": (report.get("corrida") or {}).get("condicion", "?"),
        "findings": len(report.get("hallazgos", [])),
        "confirmed": int(states.get("CONFIRMADO", 0)),
        "review": int(states.get("REQUIERE_REVISION", 0)),
        "critical": int(severities.get("CRITICA", 0)),
        "high": int(severities.get("ALTA", 0)),
        "medium": int(severities.get("MEDIA", 0)),
        "requests": int((report.get("runtime") or {}).get("peticiones_realizadas", 0)),
        "files": int((report.get("alcance") or {}).get("archivos_inventariados", 0)),
        "changed_rules": list(comparison.get("reglas_con_cambio") or []),
        "comparable": bool(comparison.get("instrumento_identico") and comparison.get("politica_identica")) if comparison else None,
        "items": list(report.get("hallazgos", [])),
    }


def options_from_payload(payload: dict[str, Any]) -> AuditOptions:
    repository_text = str(payload.get("repository", "")).strip()
    config_text = str(payload.get("config", "")).strip()
    output_text = str(payload.get("output_dir", "")).strip()
    if not repository_text or not config_text or not output_text:
        raise ValueError("Repositorio, política y carpeta de salida son obligatorios.")
    pillars_raw = payload.get("pillars", [])
    if not isinstance(pillars_raw, list):
        raise ValueError("La lista de pilares no es válida.")
    identities_raw = payload.get("identities", [])
    if not isinstance(identities_raw, list) or len(identities_raw) > 12:
        raise ValueError("La lista de identidades no es válida.")
    identities: list[IdentityCredential] = []
    for index, item in enumerate(identities_raw):
        if not isinstance(item, dict):
            raise ValueError("Cada identidad debe contener usuario y contraseña.")
        label = str(item.get("label") or chr(ord("A") + index)).strip().upper()
        if len(label) != 1 or label < "A" or label > "L":
            raise ValueError("Las identidades deben identificarse con letras entre A y L.")
        username = str(item.get("username", ""))
        password = str(item.get("password", ""))
        if any("\n" in value or "\r" in value or len(value) > 500 for value in (username, password)):
            raise ValueError(f"Los datos de la identidad {label} no son válidos.")
        identities.append(IdentityCredential(label, username, password))
    compare_text = str(payload.get("compare_with", "")).strip()
    return AuditOptions(
        repository=Path(repository_text).expanduser(),
        config=Path(config_text).expanduser(),
        output_dir=Path(output_text).expanduser(),
        pillars=tuple(sorted({int(value) for value in pillars_raw})),
        base_url=str(payload.get("base_url", "")).strip(),
        condition=str(payload.get("condition", "A")).upper(),
        compare_with=Path(compare_text).expanduser() if compare_text else None,
        generate_docx=bool(payload.get("generate_docx", True)),
        authorized=bool(payload.get("authorized", False)),
        active_tests=bool(payload.get("active_tests", False)),
        allow_network=bool(payload.get("allow_network", False)),
        fail_on=str(payload.get("fail_on", "")).upper(),
        identities=tuple(identities),
    )


class AuditRunner:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.process: subprocess.Popen[str] | None = None
        self.state: dict[str, Any] = {
            "status": "idle", "message": "Listo para configurar", "logs": [],
            "exit_code": None, "summary": None, "evidence_path": None,
            "report_path": None, "output_dir": None,
        }

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            return json.loads(json.dumps(self.state, ensure_ascii=False))

    def _set(self, **values: Any) -> None:
        with self.lock:
            self.state.update(values)

    def _log(self, line: str) -> None:
        with self.lock:
            logs = self.state.setdefault("logs", [])
            logs.append(line.rstrip())
            del logs[:-MAX_LOG_LINES]

    def start(self, options: AuditOptions) -> None:
        errors = validate_options(options)
        if errors:
            raise ValueError("\n".join(errors))
        with self.lock:
            if self.state["status"] == "running":
                raise RuntimeError("Ya existe una auditoría en ejecución.")
        options.output_dir.mkdir(parents=True, exist_ok=True)
        command = build_auditor_command(options)
        environment = build_process_environment(options)
        self._set(
            status="running", message="Auditoría en ejecución",
            logs=["Iniciando auditoría. Las credenciales permanecen solo en memoria.", subprocess.list2cmdline(command)],
            exit_code=None, summary=None, evidence_path=str(options.evidence_path),
            report_path=str(options.report_path) if options.generate_docx else None,
            output_dir=str(options.output_dir),
        )
        threading.Thread(target=self._run, args=(command, environment, options), daemon=True).start()

    def _run(self, command: list[str], environment: dict[str, str], options: AuditOptions) -> None:
        try:
            self.process = subprocess.Popen(
                command, cwd=APP_DIR, env=environment, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace",
                bufsize=1, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            assert self.process.stdout is not None
            for line in self.process.stdout:
                self._log(line)
            code = self.process.wait()
            if code in {0, 2} and options.evidence_path.is_file():
                summary = read_evidence_summary(options.evidence_path)
                message = "Auditoría finalizada" if code == 0 else "Auditoría finalizada; se alcanzó el umbral configurado"
                self._set(status="complete", message=message, exit_code=code, summary=summary)
            else:
                self._set(status="error", message=f"El auditor terminó con código {code}", exit_code=code)
        except Exception as exc:  # pragma: no cover - depende del proceso externo
            self._log(f"Error: {exc}")
            self._set(status="error", message="No se pudo completar la auditoría", exit_code=-1)
        finally:
            self.process = None

    def cancel(self) -> bool:
        process = self.process
        if process and process.poll() is None:
            process.terminate()
            self._log("Cancelación solicitada por el usuario.")
            return True
        return False

    def load_evidence(self, path: Path) -> dict[str, Any]:
        if not path.is_file():
            raise ValueError("La evidencia seleccionada no existe.")
        summary = read_evidence_summary(path)
        condition = summary["condition"]
        report = path.with_name(f"Informe_Profesional_Ciberseguridad_{condition}.docx")
        self._set(
            status="complete", message=f"Evidencia cargada: condición {condition}", summary=summary,
            evidence_path=str(path), report_path=str(report) if report.is_file() else None,
            output_dir=str(path.parent),
        )
        return summary


def _dialog_initial_directory(value: str) -> str:
    if not value.strip():
        return str(APP_DIR)
    candidate = Path(value).expanduser()
    if candidate.is_file():
        return str(candidate.parent)
    if candidate.is_dir():
        return str(candidate)
    if candidate.parent.is_dir():
        return str(candidate.parent)
    return str(APP_DIR)


def build_selector_command(kind: str, current_path: str = "") -> list[str]:
    python_executable = Path(sys.executable)
    console_python = python_executable.with_name("python.exe")
    if console_python.is_file():
        python_executable = console_python
    return [
        str(python_executable),
        str(SELECTOR_SCRIPT),
        "--kind",
        kind,
        "--initial",
        _dialog_initial_directory(current_path),
    ]


def _native_dialog(kind: str, current_path: str = "") -> str:
    if os.name != "nt":
        raise RuntimeError("El selector nativo está disponible en Windows; escriba la ruta manualmente.")
    if not SELECTOR_SCRIPT.is_file():
        raise RuntimeError("No se encontró el componente selector_archivos.py.")
    environment = dict(os.environ)
    environment["PYTHONUTF8"] = "1"
    completed = subprocess.run(
        build_selector_command(kind, current_path),
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=180,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0), check=False,
        cwd=APP_DIR, env=environment,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or "No se pudo abrir el explorador de archivos.")
    return completed.stdout.strip()


class AuditorHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], handler: type[BaseHTTPRequestHandler]) -> None:
        super().__init__(address, handler)
        self.runner = AuditRunner()
        self.token = secrets.token_urlsafe(32)


class AuditorHandler(BaseHTTPRequestHandler):
    server: AuditorHTTPServer

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _headers(self, content_type: str, length: int, status: HTTPStatus = HTTPStatus.OK) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(length))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'")
        self.end_headers()

    def _send_bytes(self, body: bytes, content_type: str, status: HTTPStatus = HTTPStatus.OK) -> None:
        self._headers(content_type, len(body), status)
        self.wfile.write(body)

    def _json(self, payload: Any, status: HTTPStatus = HTTPStatus.OK) -> None:
        self._send_bytes(json.dumps(payload, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8", status)

    def _authorized(self) -> bool:
        return secrets.compare_digest(self.headers.get("X-Auditor-Token", ""), self.server.token)

    def _read_json(self) -> dict[str, Any]:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ValueError("Longitud de solicitud inválida.") from exc
        if length <= 0 or length > MAX_REQUEST_BYTES:
            raise ValueError("La solicitud está vacía o excede el límite permitido.")
        payload = json.loads(self.rfile.read(length).decode("utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("Se esperaba un objeto JSON.")
        return payload

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        static = {
            "/": ("index.html", "text/html; charset=utf-8"),
            "/styles.css": ("styles.css", "text/css; charset=utf-8"),
            "/app.js": ("app.js", "application/javascript; charset=utf-8"),
        }
        if path in static:
            filename, content_type = static[path]
            try:
                body = (WEB_DIR / filename).read_bytes()
                if filename == "index.html":
                    body = body.replace(b"__AUDITOR_TOKEN__", self.server.token.encode("ascii"))
                self._send_bytes(body, content_type)
            except OSError as exc:
                self._json({"error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return
        if path == "/api/status":
            if not self._authorized():
                self._json({"error": "Sesión no autorizada."}, HTTPStatus.FORBIDDEN)
                return
            self._json(self.server.runner.snapshot())
            return
        self._json({"error": "Ruta no encontrada."}, HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:  # noqa: N802
        if not self._authorized():
            self._json({"error": "Sesión no autorizada."}, HTTPStatus.FORBIDDEN)
            return
        path = urlparse(self.path).path
        try:
            payload = self._read_json()
            if path == "/api/run":
                self.server.runner.start(options_from_payload(payload))
                self._json({"ok": True}, HTTPStatus.ACCEPTED)
            elif path == "/api/cancel":
                self._json({"ok": self.server.runner.cancel()})
            elif path == "/api/shutdown":
                self.server.runner.cancel()
                self._json({"ok": True, "message": "Interfaz cerrada correctamente."})
                threading.Thread(target=self.server.shutdown, daemon=True).start()
            elif path == "/api/select":
                kind = str(payload.get("kind", ""))
                if kind not in {"repository", "output", "config", "comparison"}:
                    raise ValueError("Tipo de selector no permitido.")
                current_path = str(payload.get("current", ""))
                self._json({"path": _native_dialog(kind, current_path)})
            elif path == "/api/load-evidence":
                evidence = str(payload.get("path", "")).strip()
                if not evidence:
                    raise ValueError("Seleccione una evidencia JSON.")
                self._json({"summary": self.server.runner.load_evidence(Path(evidence).expanduser())})
            elif path == "/api/open":
                state = self.server.runner.snapshot()
                key = {"report": "report_path", "evidence": "evidence_path", "output": "output_dir"}.get(str(payload.get("kind", "")))
                selected = state.get(key) if key else None
                if not selected or not Path(selected).exists():
                    raise ValueError("El artefacto solicitado no está disponible.")
                os.startfile(selected)  # type: ignore[attr-defined]
                self._json({"ok": True})
            else:
                self._json({"error": "Ruta no encontrada."}, HTTPStatus.NOT_FOUND)
        except (ValueError, RuntimeError, OSError, json.JSONDecodeError) as exc:
            self._json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Interfaz web local del auditor de ciberseguridad")
    parser.add_argument("--port", type=int, default=8765, help="puerto local; use 0 para uno automático")
    parser.add_argument("--no-browser", action="store_true", help="no abrir el navegador automáticamente")
    args = parser.parse_args(argv)
    if not 0 <= args.port <= 65535:
        parser.error("el puerto debe estar entre 0 y 65535")
    try:
        server = AuditorHTTPServer(("127.0.0.1", args.port), AuditorHandler)
    except OSError:
        if args.port == 0:
            raise
        server = AuditorHTTPServer(("127.0.0.1", 0), AuditorHandler)
    url = f"http://127.0.0.1:{server.server_address[1]}/"
    print(f"Interfaz disponible en {url}")
    print("Presione Ctrl+C para cerrar.")
    if not args.no_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        pass
    finally:
        server.runner.cancel()
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
