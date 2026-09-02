#!/usr/bin/env python3
"""Auditor local configurable para los tres pilares de seguridad.

Los pilares 1 y 2 usan pruebas HTTP declarativas, acotadas y autorizadas. El
Pilar 3 combina analisis estatico de cadena de suministro con verificacion HTTP
de la integridad del registro. El analisis estatico no instala dependencias ni
ejecuta archivos del repositorio.

Uso rapido:

    python auditor_tramitia.py --repo . --pilares 1,2,3 \
        --config auditor_config.tramitia.example.json \
        --base-url http://127.0.0.1:5050 --out evidencia.json \
        --autorizado --permitir-pruebas-activas

Solo utiliza la biblioteca estandar de Python 3.11 o posterior.
"""

from __future__ import annotations

import argparse
import base64
import fnmatch
import hashlib
import ipaddress
import json
import os
import re
import sys
import tempfile
import time
import tomllib
import uuid
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener


SCHEMA_VERSION = "1.1"
TOOL_VERSION = "1.2.0"
CONDITION_CONTROL = "B"
CONDITION_BASELINE = "A"
AUDIT_GENESIS_HASH = "sha256:" + "0" * 64

FINAL_STATES = {
    "CONFIRMADO",
    "PROBABLE",
    "DESCARTADO",
    "REQUIERE_REVISION",
}
RULE_RESULTS = {"PASS", "FAIL", "SKIP_JUSTIFICADO", "ERROR"}
SEVERITY_ORDER = {
    "INFORMATIVA": 0,
    "BAJA": 1,
    "MEDIA": 2,
    "ALTA": 3,
    "CRITICA": 4,
}

RULES: dict[str, dict[str, str]] = {
    "R-A03-001": {
        "category": "A03:2025",
        "severity": "ALTA",
        "title": "Version no fijada o referencia no reproducible",
        "recommendation": (
            "Fijar una version exacta y conservar la resolucion reproducible en "
            "un lockfile apropiado para el ecosistema."
        ),
    },
    "R-A03-002": {
        "category": "A03:2025",
        "severity": "MEDIA",
        "title": "Lockfile requerido ausente",
        "recommendation": (
            "Generar y versionar el lockfile del gestor de dependencias; no "
            "crearlo durante esta auditoria."
        ),
    },
    "R-A03-003": {
        "category": "A03:2025",
        "severity": "ALTA",
        "title": "Manifest y lockfile no son consistentes",
        "recommendation": (
            "Regenerar el lockfile de forma controlada y revisar el cambio antes "
            "de promoverlo."
        ),
    },
    "R-A03-004": {
        "category": "A03:2025",
        "severity": "ALTA",
        "title": "Coincidencia exacta en el catalogo local de advisories",
        "recommendation": (
            "Revisar el advisory local citado y actualizar, sustituir o aislar el "
            "componente segun la decision de riesgo."
        ),
    },
    "R-A03-005": {
        "category": "A03:2025",
        "severity": "MEDIA",
        "title": "Componente marcado sin mantenimiento",
        "recommendation": (
            "Planificar la migracion a un componente mantenido y registrar la "
            "excepcion si la sustitucion no es inmediata."
        ),
    },
    "R-A03-006": {
        "category": "A03:2025",
        "severity": "MEDIA",
        "title": "Procedencia ausente o no verificable",
        "recommendation": (
            "Declarar una fuente autorizada y conservar evidencia verificable de "
            "procedencia para el componente."
        ),
    },
    "R-A03-007": {
        "category": "A03:2025",
        "severity": "ALTA",
        "title": "Fuente fuera de la lista de confianza",
        "recommendation": (
            "Obtener el componente desde una fuente aprobada o incorporar la "
            "fuente mediante un cambio de politica revisado."
        ),
    },
    "R-A03-008": {
        "category": "A03:2025",
        "severity": "ALTA",
        "title": "Referencia Git o accion CI movil",
        "recommendation": (
            "Fijar la referencia al identificador completo e inmutable del commit."
        ),
    },
    "R-A08-001": {
        "category": "A08:2025",
        "severity": "MEDIA",
        "title": "Hash esperado ausente",
        "recommendation": (
            "Registrar hashes SHA-256 revisados y hacer obligatoria su "
            "verificacion antes de usar el artefacto."
        ),
    },
    "R-A08-002": {
        "category": "A08:2025",
        "severity": "CRITICA",
        "title": "El hash SHA-256 no coincide",
        "recommendation": (
            "Detener la promocion del artefacto, recuperar una copia confiable e "
            "investigar la diferencia."
        ),
    },
    "R-A08-003": {
        "category": "A08:2025",
        "severity": "ALTA",
        "title": "Descarga CI/CD sin verificacion de integridad",
        "recommendation": (
            "Verificar hash o firma en el mismo paso antes de ejecutar, instalar o "
            "promover el contenido descargado."
        ),
    },
}

DEFAULT_CONFIG: dict[str, Any] = {
    "policy_version": "pilar3-a03-a08-2026-08-29",
    "case_id": None,
    "max_files": 20_000,
    "max_file_bytes": 2 * 1024 * 1024,
    "max_total_bytes": 500 * 1024 * 1024,
    "ignore_directories": [
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        "node_modules",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".tox",
        ".nox",
        "coverage",
    ],
    "ignore_globs": [],
    "allowed_source_hosts": [
        "pypi.org",
        "files.pythonhosted.org",
        "registry.npmjs.org",
        "github.com",
        "raw.githubusercontent.com",
        "repo.maven.apache.org",
        "crates.io",
        "index.crates.io",
        "proxy.golang.org",
        "docker.io",
        "ghcr.io",
    ],
    "require_lockfiles": True,
    "require_python_hashes": True,
    "requirements_hashes_satisfy_lock": True,
    "require_explicit_provenance": False,
    "integrity_required_globs": [
        "artifacts/**",
        "dist/**/*.whl",
        "dist/**/*.jar",
        "dist/**/*.zip",
        "dist/**/*.tar.gz",
        "releases/**",
    ],
    "expected_hashes": {},
    "advisories": [],
    "ci_verification_window": 8,
    "runtime": {
        "base_url": None,
        "timeout_seconds": 5,
        "max_requests": 50,
        "max_response_bytes": 262144,
        "identities": {},
        "checks": [],
    },
}

MANIFEST_NAMES = {
    "pyproject.toml",
    "requirements.txt",
    "package.json",
    "cargo.toml",
    "go.mod",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "dockerfile",
}
SUPPORTED_LOCK_NAMES = {
    "requirements.lock",
    "requirements.lock.txt",
    "poetry.lock",
    "pdm.lock",
    "uv.lock",
    "pipfile.lock",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "cargo.lock",
    "go.sum",
    "gradle.lockfile",
}
UNSUPPORTED_MANIFEST_NAMES = {
    "gemfile",
    "gemfile.lock",
    "composer.json",
    "composer.lock",
    "packages.config",
    "mix.exs",
    "mix.lock",
    "pubspec.yaml",
    "pubspec.lock",
}


class AuditError(RuntimeError):
    """Error seguro que invalida una corrida antes de emitir conclusiones."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def audit_event_hash(
    previous_hash: str,
    event: dict[str, Any],
    *,
    hash_field: str = "hash_evento",
    previous_hash_field: str = "hash_anterior",
) -> str:
    """Calcula el hash canonico de un evento sin incluir los campos de cadena."""

    payload = {
        key: value
        for key, value in event.items()
        if key not in {hash_field, previous_hash_field}
    }
    return sha256_bytes(previous_hash.encode("utf-8") + canonical_json(payload))


def verify_audit_hash_chain(
    events: list[dict[str, Any]],
    *,
    hash_field: str = "hash_evento",
    previous_hash_field: str = "hash_anterior",
    trusted_anchor: str = AUDIT_GENESIS_HASH,
) -> dict[str, Any]:
    """Verifica una cadena completa y devuelve evidencia determinista y acotada."""

    result: dict[str, Any] = {
        "valida": False,
        "eventos_verificados": 0,
        "primer_indice_invalido": None,
        "razon": None,
        "hash_field": hash_field,
        "previous_hash_field": previous_hash_field,
        "trusted_anchor": trusted_anchor,
        "ultimo_hash": None,
    }
    if not events:
        result["razon"] = "el registro no contiene eventos"
        return result

    previous = trusted_anchor
    for index, event in enumerate(events):
        if not isinstance(event, dict):
            result["primer_indice_invalido"] = index
            result["razon"] = "el evento no es un objeto JSON"
            return result
        declared_previous = event.get(previous_hash_field)
        declared_hash = event.get(hash_field)
        if not isinstance(declared_previous, str) or not isinstance(declared_hash, str):
            result["primer_indice_invalido"] = index
            result["razon"] = "faltan hash_anterior o hash_evento"
            return result
        if declared_previous != previous:
            result["primer_indice_invalido"] = index
            result["razon"] = "hash_anterior no coincide con el evento previo"
            return result
        expected = audit_event_hash(
            previous,
            event,
            hash_field=hash_field,
            previous_hash_field=previous_hash_field,
        )
        if declared_hash != expected:
            result["primer_indice_invalido"] = index
            result["razon"] = "hash_evento no coincide con el contenido canonico"
            return result
        previous = declared_hash
        result["eventos_verificados"] = index + 1

    result["valida"] = True
    result["ultimo_hash"] = previous
    return result


def normalized_name(ecosystem: str, name: str) -> str:
    if ecosystem == "pypi":
        return re.sub(r"[-_.]+", "-", name).lower()
    if ecosystem in {"npm", "cargo", "github-actions"}:
        return name.lower()
    return name


def redact_url(value: str) -> str:
    """Elimina credenciales incrustadas antes de persistir una URL."""
    try:
        parsed = urlparse(value.replace("git+", "", 1))
    except ValueError:
        return value
    redacted = value
    if parsed.scheme and parsed.netloc and "@" in parsed.netloc:
        host = parsed.hostname or ""
        if parsed.port:
            host += f":{parsed.port}"
        redacted = parsed._replace(netloc=host).geturl()
        if value.startswith("git+"):
            redacted = "git+" + redacted
    redacted = re.sub(
        r"(?i)([?&](?:access_?token|api_?key|key|password|passwd|secret|token)=)[^&#\s]+",
        r"\1[REDACTADO]",
        redacted,
    )
    return redacted


def redact_sensitive(value: Any) -> Any:
    """Redacta credenciales en estructuras que se persistiran como evidencia."""
    if isinstance(value, dict):
        return {key: redact_sensitive(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact_sensitive(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_sensitive(item) for item in value)
    if not isinstance(value, str):
        return value
    redacted = re.sub(
        r"(?i)((?:git\+)?https?://)[^/@\s:]+:[^/@\s]+@",
        r"\1",
        value,
    )
    return re.sub(
        r"(?i)([?&](?:access_?token|api_?key|key|password|passwd|secret|token)=)[^&#\s]+",
        r"\1[REDACTADO]",
        redacted,
    )


def source_host(source: str | None) -> str | None:
    if not source:
        return None
    if source.startswith("registry:"):
        return source.split(":", 1)[1].lower().strip("/")
    cleaned = source
    for prefix in ("git+", "github:", "gitlab:", "bitbucket:"):
        if cleaned.startswith(prefix):
            cleaned = cleaned[len(prefix) :]
            break
    if cleaned.startswith("github.com/"):
        return "github.com"
    try:
        return (urlparse(cleaned).hostname or "").lower() or None
    except ValueError:
        return None


def host_allowed(host: str, allowed: Iterable[str]) -> bool:
    host = host.lower().rstrip(".")
    return any(
        host == item.lower().rstrip(".")
        or host.endswith("." + item.lower().rstrip("."))
        for item in allowed
    )


def is_full_commit(ref: str | None) -> bool:
    return bool(ref and re.fullmatch(r"[0-9a-fA-F]{40,64}", ref.strip()))


def extract_git_ref(value: str) -> str | None:
    candidate = value.strip()
    if "#" in candidate and not candidate.startswith("git+http"):
        fragment = candidate.rsplit("#", 1)[1]
        if fragment and not fragment.startswith("egg="):
            return fragment
    without_fragment = candidate.split("#", 1)[0]
    marker = without_fragment.rfind("@")
    scheme = without_fragment.find("://")
    if marker > scheme + 3:
        return without_fragment[marker + 1 :]
    return None


def exact_version(ecosystem: str, specifier: str | None) -> bool:
    if not specifier:
        return False
    value = specifier.strip().strip('"\'')
    if ecosystem == "pypi":
        return bool(re.fullmatch(r"={2,3}\s*[^*<>=!~;,\s]+", value))
    if ecosystem in {"npm", "cargo"}:
        return bool(
            re.fullmatch(r"v?\d+(?:\.\d+){1,3}(?:[-+][0-9A-Za-z.-]+)?", value)
        )
    if ecosystem == "maven":
        return not any(token in value for token in "[](),+*$") and not value.endswith(
            "-SNAPSHOT"
        )
    if ecosystem == "go":
        return bool(re.fullmatch(r"v\d+(?:\.\d+){1,2}(?:[-+][0-9A-Za-z.-]+)?", value))
    if ecosystem == "docker":
        return "@sha256:" in value
    return False


@dataclass(frozen=True)
class FileRecord:
    path: str
    size: int
    sha256: str
    kind: str
    readable: bool


@dataclass
class Component:
    ecosystem: str
    name: str
    declared_version: str | None
    resolved_version: str | None
    source: str | None
    manifest: str
    line: int | None = None
    json_path: str | None = None
    direct: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> tuple[str, str]:
        return self.ecosystem, normalized_name(self.ecosystem, self.name)

    def as_public_dict(self) -> dict[str, Any]:
        data = asdict(self)
        if data["source"]:
            data["source"] = redact_url(data["source"])
        return redact_sensitive(data)


class RepositoryReader:
    """Inventaria un arbol sin seguir enlaces ni ejecutar su contenido."""

    def __init__(
        self,
        root: Path,
        config: dict[str, Any],
        excluded_paths: Iterable[Path] = (),
    ) -> None:
        try:
            self.root = root.expanduser().resolve(strict=True)
        except OSError as exc:
            raise AuditError(f"no se puede resolver el repositorio: {exc}") from exc
        if not self.root.is_dir():
            raise AuditError(f"la ruta no es un directorio: {self.root}")
        self.config = config
        self.excluded: set[str] = set()
        for path in excluded_paths:
            try:
                self.excluded.add(path.resolve().relative_to(self.root).as_posix())
            except (OSError, ValueError):
                continue
        self.skipped_symlinks: list[str] = []
        self.skipped_large: list[str] = []
        self.records: list[FileRecord] = []
        self._by_path: dict[str, FileRecord] = {}

    def _ignored(self, relative: str) -> bool:
        if relative in self.excluded:
            return True
        return any(
            fnmatch.fnmatch(relative, pattern)
            for pattern in self.config.get("ignore_globs", [])
        )

    def inventory(self) -> list[FileRecord]:
        ignored_dirs = {str(x).lower() for x in self.config["ignore_directories"]}
        max_files = int(self.config["max_files"])
        max_file_bytes = int(self.config["max_file_bytes"])
        max_total_bytes = int(self.config["max_total_bytes"])
        total_bytes = 0
        records: list[FileRecord] = []

        for current, directories, files in os.walk(self.root, followlinks=False):
            current_path = Path(current)
            kept_directories: list[str] = []
            for name in sorted(directories):
                candidate = current_path / name
                relative = candidate.relative_to(self.root).as_posix()
                if name.lower() in ignored_dirs or self._ignored(relative + "/"):
                    continue
                if candidate.is_symlink():
                    self.skipped_symlinks.append(relative)
                    continue
                kept_directories.append(name)
            directories[:] = kept_directories

            for name in sorted(files):
                candidate = current_path / name
                relative = candidate.relative_to(self.root).as_posix()
                if self._ignored(relative):
                    continue
                if candidate.is_symlink():
                    self.skipped_symlinks.append(relative)
                    continue
                if len(records) >= max_files:
                    raise AuditError(
                        f"el repositorio supera max_files={max_files}; corrida invalida"
                    )
                try:
                    size = candidate.stat().st_size
                except OSError as exc:
                    raise AuditError(f"no se pudo inspeccionar {relative}: {exc}") from exc
                total_bytes += size
                if total_bytes > max_total_bytes:
                    raise AuditError(
                        "el repositorio supera max_total_bytes="
                        f"{max_total_bytes}; corrida invalida"
                    )
                try:
                    digest = sha256_file(candidate)
                except OSError as exc:
                    raise AuditError(f"no se pudo calcular hash de {relative}: {exc}") from exc
                readable = size <= max_file_bytes
                if not readable:
                    self.skipped_large.append(relative)
                records.append(
                    FileRecord(
                        path=relative,
                        size=size,
                        sha256=digest,
                        kind=classify_file(relative),
                        readable=readable,
                    )
                )

        self.records = sorted(records, key=lambda item: item.path)
        self._by_path = {item.path: item for item in self.records}
        return self.records

    def absolute(self, relative: str) -> Path:
        candidate = self.root / PurePosixPath(relative)
        try:
            resolved = candidate.resolve(strict=True)
            resolved.relative_to(self.root)
        except (OSError, ValueError) as exc:
            raise AuditError(f"ruta fuera del alcance: {relative}") from exc
        return resolved

    def text(self, relative: str) -> str:
        record = self._by_path.get(relative)
        if not record:
            raise AuditError(f"archivo no inventariado: {relative}")
        if not record.readable:
            raise AuditError(f"archivo excede max_file_bytes: {relative}")
        try:
            return self.absolute(relative).read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            raise AuditError(f"no se pudo leer {relative}: {exc}") from exc

    def tree_hash(self) -> str:
        digest = hashlib.sha256()
        for record in self.records:
            digest.update(record.path.encode("utf-8"))
            digest.update(b"\0")
            digest.update(record.sha256.encode("ascii"))
            digest.update(b"\0")
            digest.update(str(record.size).encode("ascii"))
            digest.update(b"\n")
        return "sha256:" + digest.hexdigest()


def classify_file(relative: str) -> str:
    path = PurePosixPath(relative)
    name = path.name.lower()
    lowered = relative.lower()
    if re.fullmatch(r"requirements(?:[-_.][^/]*)?\.txt", name) or name in {
        "requirements.lock",
        "requirements.lock.txt",
    }:
        return "python_requirements"
    if name == "pyproject.toml":
        return "python_pyproject"
    if name == "package.json":
        return "npm_manifest"
    if name in {"package-lock.json", "npm-shrinkwrap.json"}:
        return "npm_lock"
    if name in {"yarn.lock", "pnpm-lock.yaml"}:
        return "npm_lock_unsupported"
    if name == "cargo.toml":
        return "cargo_manifest"
    if name == "cargo.lock":
        return "cargo_lock"
    if name == "go.mod":
        return "go_manifest"
    if name == "go.sum":
        return "go_lock"
    if name == "pom.xml":
        return "maven_manifest"
    if name in {"build.gradle", "build.gradle.kts"}:
        return "gradle_manifest"
    if name == "gradle.lockfile" or "dependency-locks/" in lowered:
        return "gradle_lock"
    if name == "dockerfile" or name.startswith("dockerfile."):
        return "docker_manifest"
    if (
        lowered.startswith(".github/workflows/")
        or name in {".gitlab-ci.yml", "azure-pipelines.yml", "jenkinsfile"}
        or ("/ci/" in "/" + lowered and path.suffix.lower() in {".yml", ".yaml"})
    ):
        return "ci_pipeline"
    if name in {"poetry.lock", "pdm.lock", "uv.lock", "pipfile.lock"}:
        return "python_lock"
    if name in UNSUPPORTED_MANIFEST_NAMES or path.suffix.lower() == ".csproj":
        return "unsupported_manifest"
    return "other"


def _logical_requirement_lines(text: str) -> list[tuple[int, str]]:
    result: list[tuple[int, str]] = []
    buffer = ""
    start = 1
    for number, raw in enumerate(text.splitlines(), 1):
        stripped = raw.strip()
        if not buffer:
            start = number
        buffer = (buffer + " " + stripped).strip()
        if buffer.endswith("\\"):
            buffer = buffer[:-1].rstrip()
            continue
        if buffer:
            result.append((start, buffer))
        buffer = ""
    if buffer:
        result.append((start, buffer))
    return result


class ParserRegistry:
    """Parsers conservadores que nunca importan ni ejecutan el proyecto."""

    def __init__(self, reader: RepositoryReader) -> None:
        self.reader = reader
        self.components: list[Component] = []
        self.sources: list[dict[str, Any]] = []
        self.parse_errors: list[dict[str, str]] = []
        self.unsupported: list[str] = []
        self.resolved: dict[str, dict[tuple[str, str], str]] = {}

    def parse(self) -> list[Component]:
        for record in self.reader.records:
            if not record.readable and record.kind != "other":
                self.parse_errors.append(
                    {"archivo": record.path, "error": "excede max_file_bytes"}
                )
                continue
            try:
                if record.kind == "python_requirements":
                    self._requirements(record)
                elif record.kind == "python_pyproject":
                    self._pyproject(record)
                elif record.kind == "python_lock":
                    self._python_lock(record)
                elif record.kind == "npm_manifest":
                    self._package_json(record)
                elif record.kind == "npm_lock":
                    self._package_lock(record)
                elif record.kind == "cargo_manifest":
                    self._cargo_toml(record)
                elif record.kind == "cargo_lock":
                    self._cargo_lock(record)
                elif record.kind == "go_manifest":
                    self._go_mod(record)
                elif record.kind == "go_lock":
                    self._go_sum(record)
                elif record.kind == "maven_manifest":
                    self._pom(record)
                elif record.kind == "gradle_manifest":
                    self._gradle(record)
                elif record.kind == "docker_manifest":
                    self._dockerfile(record)
                elif record.kind == "ci_pipeline":
                    self._github_actions(record)
                elif record.kind in {"unsupported_manifest", "npm_lock_unsupported"}:
                    self.unsupported.append(record.path)
            except (AuditError, ET.ParseError, json.JSONDecodeError, tomllib.TOMLDecodeError) as exc:
                self.parse_errors.append({"archivo": record.path, "error": str(exc)})
        return self.components

    def _add(self, component: Component) -> None:
        if component.source:
            component.source = redact_url(component.source)
        self.components.append(component)

    def _requirements(self, record: FileRecord) -> None:
        is_lock = "lock" in PurePosixPath(record.path).name.lower()
        current_source = "registry:pypi.org"
        for number, raw in _logical_requirement_lines(self.reader.text(record.path)):
            line = re.sub(r"\s+#.*$", "", raw).strip()
            if not line or line.startswith("#"):
                continue
            option = re.match(r"--(?:extra-)?index-url(?:=|\s+)(\S+)", line)
            if option:
                current_source = redact_url(option.group(1))
                self.sources.append(
                    {"archivo": record.path, "linea": number, "fuente": current_source}
                )
                continue
            if line.startswith(("-r ", "--requirement ", "-c ", "--constraint ")):
                continue
            hashes = re.findall(r"--hash[=\s]+(sha256:[0-9a-fA-F]{64})", line)
            cleaned = re.sub(r"\s+--hash[=\s]+\S+", "", line).strip()
            cleaned = cleaned.split(";", 1)[0].strip()
            editable = cleaned.startswith(("-e ", "--editable "))
            if editable:
                cleaned = cleaned.split(maxsplit=1)[1]

            direct_match = re.match(
                r"^([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*@\s*(\S+)$", cleaned
            )
            if direct_match:
                name, source = direct_match.groups()
                ref = extract_git_ref(source) if "git" in source else None
                self._add(
                    Component(
                        ecosystem="pypi",
                        name=name,
                        declared_version=None,
                        resolved_version=None,
                        source=source,
                        manifest=record.path,
                        line=number,
                        direct=not is_lock,
                        metadata={
                            "raw": raw,
                            "hashes": hashes,
                            "git_ref": ref,
                            "is_lock": is_lock,
                            "direct_reference": True,
                        },
                    )
                )
                continue

            if cleaned.startswith(("git+", "http://", "https://")):
                egg = re.search(r"[#&]egg=([A-Za-z0-9_.-]+)", cleaned)
                name = egg.group(1) if egg else PurePosixPath(urlparse(cleaned).path).stem
                self._add(
                    Component(
                        ecosystem="pypi",
                        name=name or "dependencia-url",
                        declared_version=None,
                        resolved_version=None,
                        source=cleaned,
                        manifest=record.path,
                        line=number,
                        direct=not is_lock,
                        metadata={
                            "raw": raw,
                            "hashes": hashes,
                            "git_ref": extract_git_ref(cleaned),
                            "is_lock": is_lock,
                            "direct_reference": True,
                        },
                    )
                )
                continue

            package = re.match(r"^([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*(.*)$", cleaned)
            if not package or cleaned.startswith("-"):
                continue
            name, specifier = package.groups()
            specifier = specifier.strip() or None
            resolved = None
            if specifier and exact_version("pypi", specifier):
                resolved = re.sub(r"^={2,3}\s*", "", specifier)
            component = Component(
                ecosystem="pypi",
                name=name,
                declared_version=specifier,
                resolved_version=resolved,
                source=current_source,
                manifest=record.path,
                line=number,
                direct=not is_lock,
                metadata={"raw": raw, "hashes": hashes, "is_lock": is_lock},
            )
            self._add(component)
            if is_lock and resolved:
                self.resolved.setdefault(record.path, {})[component.key] = resolved

    def _pyproject(self, record: FileRecord) -> None:
        data = tomllib.loads(self.reader.text(record.path))
        groups: list[tuple[str, list[Any]]] = []
        project = data.get("project", {})
        groups.append(("$.project.dependencies", project.get("dependencies", []) or []))
        for group, values in (project.get("optional-dependencies", {}) or {}).items():
            groups.append((f"$.project.optional-dependencies.{group}", values or []))
        groups.append(("$.build-system.requires", data.get("build-system", {}).get("requires", []) or []))
        for json_path, values in groups:
            for index, value in enumerate(values):
                if isinstance(value, str):
                    self._pep508_component(record.path, value, f"{json_path}[{index}]")

        poetry = data.get("tool", {}).get("poetry", {})
        poetry_groups = [("$.tool.poetry.dependencies", poetry.get("dependencies", {}))]
        poetry_groups.extend(
            (
                f"$.tool.poetry.group.{group}.dependencies",
                details.get("dependencies", {}),
            )
            for group, details in (poetry.get("group", {}) or {}).items()
            if isinstance(details, dict)
        )
        for base, dependencies in poetry_groups:
            if not isinstance(dependencies, dict):
                continue
            for name, value in dependencies.items():
                if name.lower() == "python":
                    continue
                specifier: str | None = None
                source = "registry:pypi.org"
                metadata: dict[str, Any] = {"is_lock": False}
                if isinstance(value, str):
                    specifier = value
                elif isinstance(value, dict):
                    specifier = str(value.get("version")) if value.get("version") else None
                    if value.get("git"):
                        source = str(value["git"])
                        metadata["git_ref"] = value.get("rev") or value.get("tag") or value.get("branch")
                    elif value.get("url"):
                        source = str(value["url"])
                    elif value.get("path"):
                        source = "local:" + str(value["path"])
                self._add(
                    Component(
                        ecosystem="pypi",
                        name=name,
                        declared_version=specifier,
                        resolved_version=(
                            re.sub(r"^={2,3}\s*", "", specifier)
                            if specifier and exact_version("pypi", specifier)
                            else None
                        ),
                        source=source,
                        manifest=record.path,
                        json_path=f"{base}.{name}",
                        metadata=metadata,
                    )
                )

    def _pep508_component(self, manifest: str, value: str, json_path: str) -> None:
        cleaned = value.split(";", 1)[0].strip()
        direct = re.match(r"^([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*@\s*(\S+)$", cleaned)
        if direct:
            name, source = direct.groups()
            self._add(
                Component(
                    "pypi",
                    name,
                    None,
                    None,
                    source,
                    manifest,
                    json_path=json_path,
                    metadata={"direct_reference": True, "git_ref": extract_git_ref(source)},
                )
            )
            return
        match = re.match(r"^([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*(.*)$", cleaned)
        if not match:
            return
        name, specifier = match.groups()
        specifier = specifier.strip() or None
        resolved = (
            re.sub(r"^={2,3}\s*", "", specifier)
            if specifier and exact_version("pypi", specifier)
            else None
        )
        self._add(
            Component(
                "pypi",
                name,
                specifier,
                resolved,
                "registry:pypi.org",
                manifest,
                json_path=json_path,
                metadata={"is_lock": False},
            )
        )

    def _python_lock(self, record: FileRecord) -> None:
        if PurePosixPath(record.path).name.lower() == "poetry.lock":
            data = tomllib.loads(self.reader.text(record.path))
            for package in data.get("package", []):
                name, version = package.get("name"), package.get("version")
                if name and version:
                    component = Component(
                        "pypi",
                        str(name),
                        f"=={version}",
                        str(version),
                        "registry:pypi.org",
                        record.path,
                        direct=False,
                        metadata={"is_lock": True},
                    )
                    self._add(component)
                    self.resolved.setdefault(record.path, {})[component.key] = str(version)
        else:
            self.unsupported.append(record.path)

    def _package_json(self, record: FileRecord) -> None:
        data = json.loads(self.reader.text(record.path))
        for group in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
            values = data.get(group, {})
            if not isinstance(values, dict):
                continue
            for name, raw in values.items():
                specifier = str(raw)
                source = "registry:registry.npmjs.org"
                git_ref = None
                if specifier.startswith(("http://", "https://", "git+", "github:")) or "/" in specifier and "#" in specifier:
                    source = specifier
                    git_ref = extract_git_ref(specifier)
                elif specifier.startswith(("file:", "link:", "workspace:")):
                    source = "local:" + specifier
                resolved = specifier if exact_version("npm", specifier) else None
                self._add(
                    Component(
                        "npm",
                        str(name),
                        specifier,
                        resolved,
                        source,
                        record.path,
                        json_path=f"$.{group}.{name}",
                        metadata={"group": group, "git_ref": git_ref, "is_lock": False},
                    )
                )

    def _package_lock(self, record: FileRecord) -> None:
        data = json.loads(self.reader.text(record.path))
        resolved: dict[tuple[str, str], str] = {}
        packages = data.get("packages", {})
        if isinstance(packages, dict):
            for location, details in packages.items():
                if not location or not isinstance(details, dict) or not details.get("version"):
                    continue
                marker = "node_modules/"
                if marker not in location:
                    continue
                name = location.rsplit(marker, 1)[1]
                resolved[("npm", normalized_name("npm", name))] = str(details["version"])
        legacy = data.get("dependencies", {})
        if isinstance(legacy, dict):
            for name, details in legacy.items():
                if isinstance(details, dict) and details.get("version"):
                    resolved[("npm", normalized_name("npm", name))] = str(details["version"])
        self.resolved[record.path] = resolved

    def _cargo_toml(self, record: FileRecord) -> None:
        data = tomllib.loads(self.reader.text(record.path))
        for group in ("dependencies", "dev-dependencies", "build-dependencies"):
            values = data.get(group, {})
            if not isinstance(values, dict):
                continue
            for name, raw in values.items():
                specifier: str | None
                source = "registry:crates.io"
                metadata: dict[str, Any] = {"group": group, "is_lock": False}
                if isinstance(raw, str):
                    specifier = raw
                elif isinstance(raw, dict):
                    specifier = str(raw.get("version")) if raw.get("version") else None
                    if raw.get("git"):
                        source = str(raw["git"])
                        metadata["git_ref"] = raw.get("rev") or raw.get("tag") or raw.get("branch")
                    elif raw.get("path"):
                        source = "local:" + str(raw["path"])
                else:
                    continue
                self._add(
                    Component(
                        "cargo",
                        str(name),
                        specifier,
                        specifier if specifier and exact_version("cargo", specifier) else None,
                        source,
                        record.path,
                        json_path=f"$.{group}.{name}",
                        metadata=metadata,
                    )
                )

    def _cargo_lock(self, record: FileRecord) -> None:
        data = tomllib.loads(self.reader.text(record.path))
        resolved: dict[tuple[str, str], str] = {}
        for package in data.get("package", []):
            if package.get("name") and package.get("version"):
                resolved[("cargo", normalized_name("cargo", str(package["name"])))] = str(package["version"])
        self.resolved[record.path] = resolved

    def _go_mod(self, record: FileRecord) -> None:
        in_require = False
        for number, raw in enumerate(self.reader.text(record.path).splitlines(), 1):
            line = raw.split("//", 1)[0].strip()
            if line == "require (":
                in_require = True
                continue
            if in_require and line == ")":
                in_require = False
                continue
            if line.startswith("require "):
                line = line[len("require ") :].strip()
            elif not in_require:
                continue
            parts = line.split()
            if len(parts) >= 2:
                name, version = parts[:2]
                self._add(
                    Component(
                        "go",
                        name,
                        version,
                        version if exact_version("go", version) else None,
                        "registry:proxy.golang.org",
                        record.path,
                        line=number,
                        metadata={"raw": raw, "is_lock": False},
                    )
                )

    def _go_sum(self, record: FileRecord) -> None:
        resolved: dict[tuple[str, str], str] = {}
        for raw in self.reader.text(record.path).splitlines():
            parts = raw.split()
            if len(parts) >= 2:
                version = parts[1].removesuffix("/go.mod")
                resolved[("go", normalized_name("go", parts[0]))] = version
        self.resolved[record.path] = resolved

    def _pom(self, record: FileRecord) -> None:
        root = ET.fromstring(self.reader.text(record.path))
        namespace = ""
        if root.tag.startswith("{"):
            namespace = root.tag.split("}", 1)[0] + "}"
        properties: dict[str, str] = {}
        props = root.find(f"{namespace}properties")
        if props is not None:
            for child in props:
                properties[child.tag.split("}")[-1]] = (child.text or "").strip()
        for repo in root.findall(f".//{namespace}repository/{namespace}url"):
            if repo.text:
                self.sources.append(
                    {"archivo": record.path, "linea": None, "fuente": redact_url(repo.text.strip())}
                )
        for dependency in root.findall(f".//{namespace}dependencies/{namespace}dependency"):
            group = dependency.findtext(f"{namespace}groupId") or ""
            artifact = dependency.findtext(f"{namespace}artifactId") or ""
            version = dependency.findtext(f"{namespace}version")
            if version and version.startswith("${") and version.endswith("}"):
                version = properties.get(version[2:-1], version)
            if group and artifact:
                self._add(
                    Component(
                        "maven",
                        f"{group}:{artifact}",
                        version,
                        version if exact_version("maven", version) else None,
                        "registry:repo.maven.apache.org",
                        record.path,
                        json_path=f"//dependency[{group}:{artifact}]",
                        metadata={"is_lock": False},
                    )
                )

    def _gradle(self, record: FileRecord) -> None:
        pattern = re.compile(
            r"(?:implementation|api|compileOnly|runtimeOnly|testImplementation)\s*[('\\\"]+([^:'\\\"]+):([^:'\\\"]+):([^'\\\")\s]+)"
        )
        for number, raw in enumerate(self.reader.text(record.path).splitlines(), 1):
            match = pattern.search(raw)
            if match:
                group, name, version = match.groups()
                self._add(
                    Component(
                        "maven",
                        f"{group}:{name}",
                        version,
                        version if exact_version("maven", version) else None,
                        "registry:repo.maven.apache.org",
                        record.path,
                        line=number,
                        metadata={"raw": raw, "gradle": True, "is_lock": False},
                    )
                )

    def _dockerfile(self, record: FileRecord) -> None:
        for number, raw in enumerate(self.reader.text(record.path).splitlines(), 1):
            match = re.match(r"\s*FROM\s+(?:--platform=\S+\s+)?(\S+)", raw, re.I)
            if not match:
                continue
            image = match.group(1)
            if image.lower() == "scratch" or image.startswith("${"):
                continue
            name = image
            if "@" in image:
                name = image.split("@", 1)[0]
            elif ":" in image.rsplit("/", 1)[-1]:
                name = image.rsplit(":", 1)[0]
            host = image.split("/", 1)[0] if "/" in image and ("." in image.split("/", 1)[0] or ":" in image.split("/", 1)[0]) else "docker.io"
            self._add(
                Component(
                    "docker",
                    name,
                    image,
                    image if exact_version("docker", image) else None,
                    "registry:" + host,
                    record.path,
                    line=number,
                    metadata={"raw": raw, "is_lock": False},
                )
            )

    def _github_actions(self, record: FileRecord) -> None:
        if not record.path.lower().startswith(".github/workflows/"):
            return
        for number, raw in enumerate(self.reader.text(record.path).splitlines(), 1):
            match = re.match(r"\s*-?\s*uses:\s*['\"]?([^'\"#\s]+)", raw)
            if not match:
                continue
            value = match.group(1)
            if value.startswith("./") or "@" not in value:
                continue
            name, ref = value.rsplit("@", 1)
            self._add(
                Component(
                    "github-actions",
                    name,
                    ref,
                    ref if is_full_commit(ref) else None,
                    "https://github.com/" + name,
                    record.path,
                    line=number,
                    metadata={"raw": raw, "git_ref": ref, "is_lock": False},
                )
            )


def _merge_config(base: dict[str, Any], overrides: dict[str, Any]) -> dict[str, Any]:
    result = dict(base)
    for key, value in overrides.items():
        result[key] = value
    return result


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AuditError(f"no se pudo cargar {path}: {exc}") from exc


def load_config(config: dict[str, Any] | str | Path | None) -> tuple[dict[str, Any], dict[str, str]]:
    hashes: dict[str, str] = {}
    base_dir = Path.cwd()
    overrides: dict[str, Any] = {}
    if isinstance(config, (str, Path)):
        config_path = Path(config).expanduser().resolve(strict=True)
        loaded = _load_json(config_path)
        if not isinstance(loaded, dict):
            raise AuditError("el archivo de configuracion debe contener un objeto JSON")
        overrides = loaded
        base_dir = config_path.parent
        hashes["config_file"] = sha256_file(config_path)
    elif isinstance(config, dict):
        overrides = dict(config)
    elif config is not None:
        raise AuditError("configuracion debe ser objeto, ruta o None")

    merged = _merge_config(DEFAULT_CONFIG, overrides)
    external_specs = (
        ("trusted_sources_file", "allowed_source_hosts", "hosts"),
        ("expected_hashes_file", "expected_hashes", "files"),
        ("advisory_dataset_file", "advisories", "advisories"),
    )
    for path_key, target_key, nested_key in external_specs:
        if not merged.get(path_key):
            continue
        external = (base_dir / str(merged[path_key])).resolve(strict=True)
        payload = _load_json(external)
        if isinstance(payload, dict) and nested_key in payload:
            payload = payload[nested_key]
        merged[target_key] = payload
        hashes[path_key] = sha256_file(external)

    if not isinstance(merged.get("allowed_source_hosts"), list):
        raise AuditError("allowed_source_hosts debe ser una lista")
    if not isinstance(merged.get("expected_hashes"), dict):
        raise AuditError("expected_hashes debe ser un objeto ruta->sha256")
    if not isinstance(merged.get("advisories"), list):
        raise AuditError("advisories debe ser una lista")
    merged["allowed_source_hosts"] = sorted(
        {str(item).lower().rstrip(".") for item in merged["allowed_source_hosts"]}
    )
    merged["expected_hashes"] = {
        str(path).replace("\\", "/"): str(digest)
        for path, digest in merged["expected_hashes"].items()
    }
    hashes["effective_config"] = sha256_bytes(canonical_json(merged))
    return merged, hashes


@dataclass(frozen=True)
class HttpResponse:
    status: int
    headers: dict[str, str]
    body: bytes
    truncated: bool = False

    @property
    def body_sha256(self) -> str:
        return sha256_bytes(self.body)

    def json(self) -> Any:
        try:
            return json.loads(self.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AuditError("la respuesta HTTP no contiene JSON valido") from exc

    def evidence(self, selected_headers: Iterable[str] = ()) -> dict[str, Any]:
        headers = {
            name.lower(): self.headers.get(name.lower())
            for name in selected_headers
            if self.headers.get(name.lower()) is not None
        }
        return {
            "status": self.status,
            "headers": headers,
            "body_sha256": self.body_sha256,
            "body_bytes_conservados": len(self.body),
            "truncado": self.truncated,
        }


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


def _loopback_host(host: str | None) -> bool:
    if not host:
        return False
    if host.lower().rstrip(".") == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class HttpClient:
    """Cliente HTTP acotado al origen autorizado y sin redirecciones."""

    def __init__(
        self,
        base_url: str,
        *,
        timeout: float = 5,
        max_requests: int = 50,
        max_response_bytes: int = 262_144,
        allow_non_loopback: bool = False,
    ) -> None:
        parsed = urlparse(base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise AuditError("base_url debe ser una URL HTTP(S) absoluta")
        if parsed.username or parsed.password:
            raise AuditError("base_url no puede contener credenciales")
        if not allow_non_loopback and not _loopback_host(parsed.hostname):
            raise AuditError(
                "por defecto solo se permite localhost; use --permitir-red de forma explicita"
            )
        self.origin = f"{parsed.scheme}://{parsed.netloc}"
        prefix = parsed.path.rstrip("/")
        self.base_url = self.origin + prefix
        self.timeout = float(timeout)
        self.max_requests = int(max_requests)
        self.max_response_bytes = int(max_response_bytes)
        self.request_count = 0
        self.opener = build_opener(_NoRedirect())

    def request(
        self,
        method: str,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        json_body: Any = None,
        username: str | None = None,
        password: str | None = None,
    ) -> HttpResponse:
        if self.request_count >= self.max_requests:
            raise AuditError(
                f"se alcanzo max_requests={self.max_requests}; corrida runtime incompleta"
            )
        target = urlparse(path)
        if target.scheme or target.netloc or not path.startswith("/"):
            raise AuditError("cada request.path debe ser relativo al origen y empezar por /")
        url = self.base_url + path
        if not url.startswith(self.origin):
            raise AuditError("la peticion intentaria salir del origen autorizado")

        request_headers = {
            "Accept": "application/json",
            "User-Agent": f"auditor-tramitia/{TOOL_VERSION}",
        }
        request_headers.update({str(k): str(v) for k, v in (headers or {}).items()})
        if username is not None:
            if password is None:
                raise AuditError("la identidad runtime no tiene password")
            token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
            request_headers["Authorization"] = f"Basic {token}"
        body = None
        if json_body is not None:
            body = canonical_json(json_body)
            request_headers.setdefault("Content-Type", "application/json")
        req = Request(url, data=body, headers=request_headers, method=method.upper())
        self.request_count += 1
        try:
            response = self.opener.open(req, timeout=self.timeout)
            status = int(response.status)
            response_headers = {key.lower(): value for key, value in response.headers.items()}
            content = response.read(self.max_response_bytes + 1)
        except HTTPError as exc:
            status = int(exc.code)
            response_headers = {key.lower(): value for key, value in exc.headers.items()}
            content = exc.read(self.max_response_bytes + 1)
        except (URLError, TimeoutError, OSError) as exc:
            raise AuditError(f"fallo de conexion con la instancia autorizada: {exc}") from exc
        truncated = len(content) > self.max_response_bytes
        return HttpResponse(
            status=status,
            headers=response_headers,
            body=content[: self.max_response_bytes],
            truncated=truncated,
        )


def json_path_get(payload: Any, path: str) -> Any:
    if path == "$":
        return payload
    if not path.startswith("$."):
        raise AuditError(f"json_path no soportado: {path}")
    current = payload
    tokens = re.findall(r"(?:^|\.)([^.\[\]]+)|\[(\d+)\]", path[2:])
    if not tokens:
        raise AuditError(f"json_path no soportado: {path}")
    for key, index in tokens:
        if key:
            if not isinstance(current, dict) or key not in current:
                raise AuditError(f"json_path inexistente: {path}")
            current = current[key]
        else:
            position = int(index)
            if not isinstance(current, list) or position >= len(current):
                raise AuditError(f"json_path inexistente: {path}")
            current = current[position]
    return current


def pilar1_escalada_agente(
    payload: Any,
    *,
    json_path: str = "$.identidad_efectiva.role",
    disallowed_values: Iterable[Any] = ("coordinador", "admin", "administrator"),
) -> dict[str, Any]:
    """Evalua de forma determinista la identidad efectiva reportada por el agente."""

    observed = json_path_get(payload, json_path)
    disallowed = list(disallowed_values)
    vulnerable = observed in disallowed
    return {
        "vulnerable": vulnerable,
        "json_path": json_path,
        "valor_observado": observed,
        "valores_prohibidos": disallowed,
    }


def pilar1_alcance_agente(
    direct_payload: Any,
    agent_payload: Any,
    *,
    direct_json_path: str = "$",
    steps_json_path: str = "$.pasos",
    tool_name: str = "listar_solicitudes",
    tool_field: str = "herramienta",
    count_field: str = "devueltas",
    id_field: str = "id",
    agent_items_json_path: str | None = None,
) -> dict[str, Any]:
    """Compara lo que una identidad ve por la API directa con lo que obtiene via el agente.

    La API directa es la referencia autorizada: define cuantos objetos puede ver la
    identidad. Si la herramienta del agente devuelve mas objetos (o identificadores
    que la API directa no entrega), el agente esta ejecutando con una identidad
    distinta a la del solicitante. La medicion no depende del rol que el agente
    declare sobre si mismo.
    """

    direct_items = json_path_get(direct_payload, direct_json_path)
    if not isinstance(direct_items, list):
        raise AuditError("direct_json_path no apunta a una lista")
    direct_ids = sorted(
        {
            str(item[id_field])
            for item in direct_items
            if isinstance(item, dict) and id_field in item
        }
    )

    steps = json_path_get(agent_payload, steps_json_path)
    if not isinstance(steps, list):
        raise AuditError("steps_json_path no apunta a una lista")
    invocations = [
        step
        for step in steps
        if isinstance(step, dict) and str(step.get(tool_field)) == tool_name
    ]
    counts = [
        int(step[count_field])
        for step in invocations
        if isinstance(step.get(count_field), int)
        and not isinstance(step.get(count_field), bool)
    ]
    agent_count: int | None = max(counts) if counts else None

    agent_ids: list[str] | None = None
    exposed_ids: list[str] | None = None
    if agent_items_json_path:
        agent_items = json_path_get(agent_payload, agent_items_json_path)
        if not isinstance(agent_items, list):
            raise AuditError("agent_items_json_path no apunta a una lista")
        agent_ids = sorted(
            {
                str(item[id_field])
                for item in agent_items
                if isinstance(item, dict) and id_field in item
            }
        )
        exposed_ids = sorted(set(agent_ids) - set(direct_ids))
        if agent_count is None:
            agent_count = len(agent_items)

    precondition_valid = agent_count is not None
    vulnerable = precondition_valid and (
        agent_count > len(direct_items) or bool(exposed_ids)
    )
    return {
        "precondicion_valida": precondition_valid,
        "vulnerable": vulnerable,
        "herramienta": tool_name,
        "invocaciones_herramienta": len(invocations),
        "cantidad_api_directa": len(direct_items),
        "cantidad_agente": agent_count,
        "ids_api_directa": direct_ids,
        "ids_agente": agent_ids,
        "ids_expuestos_por_agente": exposed_ids,
        "exceso": (agent_count - len(direct_items)) if agent_count is not None else None,
    }


def pilar2_urgente_bypass(
    normal_statuses: Iterable[int],
    urgent_statuses: Iterable[int],
    *,
    limited_statuses: Iterable[int] = (429,),
) -> dict[str, Any]:
    """Compara el mismo lote normal y urgente frente al presupuesto del agente."""

    normal = [int(status) for status in normal_statuses]
    urgent = [int(status) for status in urgent_statuses]
    limited = {int(status) for status in limited_statuses}
    normal_limited = any(status in limited for status in normal)
    urgent_limited = any(status in limited for status in urgent)
    return {
        "precondicion_valida": normal_limited,
        "vulnerable": normal_limited and not urgent_limited,
        "codigos_normal": normal,
        "codigos_urgente": urgent,
        "normal_limitado": normal_limited,
        "urgente_limitado": urgent_limited,
        "codigos_de_limite": sorted(limited),
    }


def pilar3_auditoria_sin_firma(
    events: list[dict[str, Any]],
    *,
    hash_field: str = "hash_evento",
    previous_hash_field: str = "hash_anterior",
    trusted_anchor: str = AUDIT_GENESIS_HASH,
) -> dict[str, Any]:
    """Verifica la cadena y demuestra deteccion sobre una copia alterada en memoria."""

    verification = verify_audit_hash_chain(
        events,
        hash_field=hash_field,
        previous_hash_field=previous_hash_field,
        trusted_anchor=trusted_anchor,
    )
    tamper_detected = False
    tampered_verification: dict[str, Any] | None = None
    if verification["valida"]:
        tampered = [dict(event) for event in events]
        tampered[0]["_prueba_alteracion_controlada"] = True
        tampered_verification = verify_audit_hash_chain(
            tampered,
            hash_field=hash_field,
            previous_hash_field=previous_hash_field,
            trusted_anchor=trusted_anchor,
        )
        tamper_detected = not tampered_verification["valida"]
    return {
        "vulnerable": not verification["valida"] or not tamper_detected,
        "cadena": verification,
        "alteracion_controlada_detectada": tamper_detected,
        "verificacion_copia_alterada": tampered_verification,
    }


class RuntimeAuditor:
    """Ejecuta controles declarativos de runtime para los tres pilares."""

    SUPPORTED_TYPES = {
        "auth_required",
        "cross_object_access",
        "role_boundary",
        "json_value_policy",
        "agent_scope_consistency",
        "brute_force_protection",
        "rate_limit_bypass",
        "cors_policy",
        "security_headers",
        "error_disclosure",
        "body_limit",
        "source_regex_absent",
        "audit_hash_chain",
    }

    def __init__(
        self,
        root: Path,
        config: dict[str, Any],
        run: dict[str, Any],
        client: Any | None,
        *,
        selected_pillars: set[int],
        active_tests_authorized: bool,
    ) -> None:
        self.root = root.resolve(strict=True)
        self.config = config
        self.runtime = config.get("runtime", {}) or {}
        self.run = run
        self.client = client
        self.selected_pillars = selected_pillars
        self.active_tests_authorized = active_tests_authorized
        self.events: list[dict[str, Any]] = []
        self.findings: list[dict[str, Any]] = []

    def execute(self) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        checks = self.runtime.get("checks", [])
        if not isinstance(checks, list):
            raise AuditError("runtime.checks debe ser una lista")
        seen_ids: set[str] = set()
        for check in checks:
            if not isinstance(check, dict):
                raise AuditError("cada control runtime debe ser un objeto")
            pillar = int(check.get("pillar", 0))
            if pillar not in self.selected_pillars:
                continue
            check_id = str(check.get("id") or "")
            if not check_id or check_id in seen_ids:
                raise AuditError("cada control runtime requiere un id unico")
            seen_ids.add(check_id)
            check_type = str(check.get("type") or "")
            if check_type not in self.SUPPORTED_TYPES:
                self._emit(check, "ERROR", detail=f"tipo de control no soportado: {check_type}")
                continue
            if check.get("active") and not self.active_tests_authorized:
                self._emit(
                    check,
                    "SKIP_JUSTIFICADO",
                    detail="requiere --permitir-pruebas-activas",
                )
                continue
            try:
                getattr(self, f"_check_{check_type}")(check)
            except AuditError as exc:
                self._emit(check, "ERROR", detail=str(exc), confidence="MEDIA")
        return self.events, self.findings

    def _emit(
        self,
        check: dict[str, Any],
        result: str,
        *,
        evidence: list[dict[str, Any]] | None = None,
        detail: str | None = None,
        confidence: str = "ALTA",
        endpoint: str | None = None,
        line: int | None = None,
        file: str | None = None,
    ) -> None:
        if result not in RULE_RESULTS:
            raise AuditError(f"resultado runtime invalido: {result}")
        pillar = int(check["pillar"])
        check_id = str(check["id"])
        safe_evidence = redact_sensitive(evidence or [])
        event = {
            "pilar": pillar,
            "regla_id": check_id,
            "resultado": result,
            "archivo": file,
            "endpoint": endpoint,
            "ubicacion": {
                "linea_inicio": line,
                "linea_fin": line,
                "json_path": check.get("json_path"),
            },
            "componente": endpoint,
            "detalle": detail,
            "evidencia": safe_evidence,
        }
        self.events.append(event)
        if result not in {"FAIL", "ERROR"}:
            return
        default_categories = {
            1: "OWASP Top 10:2021 A01 Broken Access Control",
            2: "OWASP Top 10:2021 A04 Insecure Design",
            3: "OWASP Top 10:2021 A09 Security Logging and Monitoring Failures",
        }
        category = str(check.get("category") or default_categories[pillar])
        severity = str(check.get("severity") or "ALTA").upper()
        if severity not in SEVERITY_ORDER:
            severity = "ALTA"
        final_state = "CONFIRMADO" if result == "FAIL" else "REQUIERE_REVISION"
        self.findings.append(
            {
                "pilar": pillar,
                "corrida_id": self.run["corrida_id"],
                "timestamp_utc": self.run["timestamp_utc"],
                "condicion": self.run["condicion"],
                "modo_control": self.run["modo_control"],
                "repo_hash": self.run["repo_hash"],
                "caso_id": self.config.get("case_id") or self.root.name,
                "archivo": file,
                "endpoint": endpoint,
                "ubicacion": event["ubicacion"],
                "tipo_archivo": classify_file(file) if file else "http_test",
                "componente": endpoint,
                "ecosistema": "http" if endpoint else "source",
                "version": None,
                "categoria_owasp": category,
                "regla_id": check_id,
                "hallazgo": str(check.get("title") or check_id),
                "severidad": severity,
                "detalle": detail,
                "evidencia": safe_evidence,
                "origen_procedencia": {
                    "valor": getattr(self.client, "base_url", None),
                    "verificable": self.client is not None,
                },
                "resultado_determinista": {"ejecutada": True, "resultado": result},
                "confianza": confidence,
                "recomendacion": str(
                    check.get("recommendation")
                    or "Aplicar el control indicado y repetir exactamente la misma prueba."
                ),
                "estado_final": final_state,
            }
        )

    def _identity(self, name: str | None) -> tuple[str | None, str | None]:
        if not name:
            return None, None
        identities = self.runtime.get("identities", {})
        details = identities.get(name) if isinstance(identities, dict) else None
        if not isinstance(details, dict):
            match = re.fullmatch(r"usuario_([a-lA-L])", name)
            if not match:
                raise AuditError(f"identidad runtime no configurada: {name}")
            label = match.group(1).upper()
            details = {
                "username_env": f"AUDITOR_TRAMITIA_USER_{label}",
                "password_env": f"AUDITOR_TRAMITIA_PASSWORD_{label}",
            }
        username = details.get("username")
        password = details.get("password")
        if details.get("username_env"):
            username = os.getenv(str(details["username_env"]))
        if details.get("password_env"):
            password = os.getenv(str(details["password_env"]))
        if not username or password is None:
            raise AuditError(f"faltan variables de entorno para la identidad {name}")
        return str(username), str(password)

    def _request(
        self,
        check: dict[str, Any],
        *,
        identity_name: str | None = None,
        password_override: str | None = None,
        json_override: Any = None,
        headers_override: dict[str, str] | None = None,
    ) -> tuple[HttpResponse, str]:
        if self.client is None:
            raise AuditError("el control requiere base_url")
        request_spec = check.get("request", {})
        if not isinstance(request_spec, dict):
            raise AuditError("request debe ser un objeto")
        method = str(request_spec.get("method") or "GET").upper()
        path = str(request_spec.get("path") or "")
        if not path:
            raise AuditError("request.path es obligatorio")
        selected_identity = identity_name
        if selected_identity is None:
            selected_identity = request_spec.get("identity") or check.get("identity")
        username, password = self._identity(str(selected_identity) if selected_identity else None)
        if password_override is not None:
            password = password_override
        headers = {str(k): str(v) for k, v in (request_spec.get("headers", {}) or {}).items()}
        headers.update(headers_override or {})
        json_body = request_spec.get("json") if json_override is None else json_override
        response = self.client.request(
            method,
            path,
            headers=headers,
            json_body=json_body,
            username=username,
            password=password,
        )
        return response, path

    @staticmethod
    def _statuses(check: dict[str, Any], key: str, default: list[int]) -> set[int]:
        expected = check.get("expected", {})
        values = expected.get(key, default) if isinstance(expected, dict) else default
        return {int(item) for item in values}

    def _check_auth_required(self, check: dict[str, Any]) -> None:
        response, path = self._request(check, identity_name="")
        denied = self._statuses(check, "denied_status", [401, 403])
        passed = response.status in denied
        self._emit(
            check,
            "PASS" if passed else "FAIL",
            endpoint=path,
            evidence=[{"tipo": "respuesta_sin_autenticacion", "valor": response.evidence()}],
            detail="el endpoint rechazo la peticion anonima" if passed else "el endpoint no rechazo la peticion anonima",
        )

    def _check_cross_object_access(self, check: dict[str, Any]) -> None:
        owner, path = self._request(check, identity_name=str(check.get("owner_identity") or ""))
        other, _ = self._request(check, identity_name=str(check.get("other_identity") or ""))
        allowed = self._statuses(check, "owner_status", [200])
        denied = self._statuses(check, "denied_status", [403, 404])
        evidence = [
            {"tipo": "status_propietario", "valor": owner.status},
            {"tipo": "status_otro_usuario", "valor": other.status},
        ]
        if owner.status not in allowed:
            self._emit(
                check,
                "ERROR",
                endpoint=path,
                evidence=evidence,
                detail="la precondicion fallo: el propietario no pudo acceder al objeto",
            )
            return
        passed = other.status in denied
        self._emit(
            check,
            "PASS" if passed else "FAIL",
            endpoint=path,
            evidence=evidence,
            detail="el acceso cruzado fue rechazado" if passed else "otro usuario obtuvo acceso al objeto",
        )

    def _check_role_boundary(self, check: dict[str, Any]) -> None:
        response, path = self._request(check)
        denied = self._statuses(check, "denied_status", [403, 404])
        passed = response.status in denied
        self._emit(
            check,
            "PASS" if passed else "FAIL",
            endpoint=path,
            evidence=[{"tipo": "status_rol_bajo", "valor": response.status}],
            detail="el limite de rol fue aplicado" if passed else "la identidad de bajo privilegio alcanzo el endpoint",
        )

    def _check_json_value_policy(self, check: dict[str, Any]) -> None:
        response, path = self._request(check)
        accepted = self._statuses(check, "status", [200])
        if response.status not in accepted:
            self._emit(
                check,
                "ERROR",
                endpoint=path,
                evidence=[{"tipo": "respuesta_http", "valor": response.evidence()}],
                detail="la respuesta no cumplio la precondicion HTTP",
            )
            return
        json_path = str(check.get("json_path") or "")
        payload = response.json()
        evaluation = pilar1_escalada_agente(
            payload,
            json_path=json_path,
            disallowed_values=check.get("disallowed_values", []),
        )
        unsafe = bool(evaluation["vulnerable"])
        self._emit(
            check,
            "FAIL" if unsafe else "PASS",
            endpoint=path,
            evidence=[
                {"tipo": "json_path", "valor": json_path},
                {"tipo": "valor_observado", "valor": evaluation["valor_observado"]},
                {"tipo": "respuesta_json", "valor": redact_sensitive(payload)},
            ],
            detail="el valor observado esta prohibido por la politica" if unsafe else "el valor observado cumple la politica",
        )

    def _check_agent_scope_consistency(self, check: dict[str, Any]) -> None:
        direct_spec = check.get("direct_request")
        if not isinstance(direct_spec, dict):
            raise AuditError("agent_scope_consistency requiere direct_request")
        accepted = self._statuses(check, "status", [200])

        direct, direct_path = self._request({**check, "request": direct_spec})
        if direct.status not in accepted:
            self._emit(
                check,
                "ERROR",
                endpoint=direct_path,
                evidence=[{"tipo": "respuesta_api_directa", "valor": direct.evidence()}],
                detail="la API directa no cumplio la precondicion HTTP",
            )
            return

        agent, path = self._request(check)
        if agent.status not in accepted:
            self._emit(
                check,
                "ERROR",
                endpoint=path,
                evidence=[
                    {"tipo": "respuesta_api_directa", "valor": direct.evidence()},
                    {"tipo": "respuesta_agente", "valor": agent.evidence()},
                ],
                detail="la respuesta del agente no cumplio la precondicion HTTP",
            )
            return

        evaluation = pilar1_alcance_agente(
            direct.json(),
            agent.json(),
            direct_json_path=str(check.get("direct_json_path") or "$"),
            steps_json_path=str(check.get("steps_json_path") or "$.pasos"),
            tool_name=str(check.get("tool_name") or "listar_solicitudes"),
            tool_field=str(check.get("tool_field") or "herramienta"),
            count_field=str(check.get("count_field") or "devueltas"),
            id_field=str(check.get("id_field") or "id"),
            agent_items_json_path=check.get("agent_items_json_path"),
        )
        evidence = [
            {"tipo": "endpoint_api_directa", "valor": direct_path},
            {"tipo": "respuesta_api_directa", "valor": direct.evidence()},
            {"tipo": "respuesta_agente", "valor": agent.evidence()},
            {"tipo": "herramienta_observada", "valor": evaluation["herramienta"]},
            {"tipo": "invocaciones_herramienta", "valor": evaluation["invocaciones_herramienta"]},
            {"tipo": "cantidad_api_directa", "valor": evaluation["cantidad_api_directa"]},
            {"tipo": "cantidad_agente", "valor": evaluation["cantidad_agente"]},
            {"tipo": "exceso", "valor": evaluation["exceso"]},
            {"tipo": "ids_api_directa", "valor": evaluation["ids_api_directa"]},
            {"tipo": "ids_expuestos_por_agente", "valor": evaluation["ids_expuestos_por_agente"]},
        ]
        if not evaluation["precondicion_valida"]:
            self._emit(
                check,
                "ERROR",
                endpoint=path,
                evidence=evidence,
                detail=(
                    "el modelo no invoco la herramienta observada; el alcance no es "
                    "medible en esta corrida y no debe interpretarse como PASS"
                ),
                confidence="MEDIA",
            )
            return
        vulnerable = bool(evaluation["vulnerable"])
        self._emit(
            check,
            "FAIL" if vulnerable else "PASS",
            endpoint=path,
            evidence=evidence,
            detail=(
                "el agente devolvio mas objetos de los que la identidad ve por la API directa"
                if vulnerable
                else "el alcance del agente coincide con el de la API directa para la misma identidad"
            ),
        )

    def _check_brute_force_protection(self, check: dict[str, Any]) -> None:
        attempts = int(check.get("attempts", 8))
        if attempts < 2 or attempts > 10:
            raise AuditError("attempts debe estar entre 2 y 10")
        statuses: list[int] = []
        path = ""
        for index in range(attempts):
            response, path = self._request(
                check,
                password_override=f"auditoria-invalida-{index}-{self.run['corrida_id'][:8]}",
            )
            statuses.append(response.status)
        throttle = self._statuses(check, "throttle_status", [423, 429])
        protected = any(status in throttle for status in statuses)
        self._emit(
            check,
            "PASS" if protected else "FAIL",
            endpoint=path,
            evidence=[{"tipo": "codigos_http", "valor": statuses}],
            detail="aparecio una respuesta de bloqueo o limitacion" if protected else "todos los intentos terminaron sin bloqueo o limitacion",
        )

    def _check_rate_limit_bypass(self, check: dict[str, Any]) -> None:
        count = int(check.get("requests_per_variant", 5))
        if count < 2 or count > 10:
            raise AuditError("requests_per_variant debe estar entre 2 y 10")
        normal_body = check.get("normal_json")
        bypass_body = check.get("bypass_json")
        normal: list[int] = []
        bypass: list[int] = []
        path = ""
        for _ in range(count):
            response, path = self._request(check, json_override=normal_body)
            normal.append(response.status)
        for _ in range(count):
            response, path = self._request(check, json_override=bypass_body)
            bypass.append(response.status)
        limited = self._statuses(check, "limited_status", [429])
        evaluation = pilar2_urgente_bypass(
            normal,
            bypass,
            limited_statuses=limited,
        )
        evidence = [
            {"tipo": "codigos_normal", "valor": evaluation["codigos_normal"]},
            {"tipo": "codigos_urgente", "valor": evaluation["codigos_urgente"]},
            {"tipo": "normal_limitado", "valor": evaluation["normal_limitado"]},
            {"tipo": "urgente_limitado", "valor": evaluation["urgente_limitado"]},
        ]
        if not evaluation["precondicion_valida"]:
            self._emit(
                check,
                "ERROR",
                endpoint=path,
                evidence=evidence,
                detail="la variante normal no alcanzo el limite; ajuste el presupuesto de prueba",
            )
            return
        vulnerable = bool(evaluation["vulnerable"])
        self._emit(
            check,
            "FAIL" if vulnerable else "PASS",
            endpoint=path,
            evidence=evidence,
            detail="la variante alternativa evadio el limite" if vulnerable else "ambas variantes quedaron sujetas al limite",
        )

    def _check_cors_policy(self, check: dict[str, Any]) -> None:
        origin = str(check.get("origin") or "https://origen-no-confiable.example")
        response, path = self._request(check, headers_override={"Origin": origin})
        allow_origin = response.headers.get("access-control-allow-origin")
        allow_credentials = response.headers.get("access-control-allow-credentials", "").lower()
        vulnerable = allow_origin == origin and allow_credentials == "true"
        self._emit(
            check,
            "FAIL" if vulnerable else "PASS",
            endpoint=path,
            evidence=[
                {"tipo": "origin_enviado", "valor": origin},
                {"tipo": "access_control_allow_origin", "valor": allow_origin},
                {"tipo": "access_control_allow_credentials", "valor": allow_credentials or None},
            ],
            detail="el origen arbitrario fue reflejado con credenciales" if vulnerable else "no se observo reflexion CORS peligrosa",
        )

    def _check_security_headers(self, check: dict[str, Any]) -> None:
        response, path = self._request(check)
        required = check.get("required_headers", {})
        if not isinstance(required, dict):
            raise AuditError("required_headers debe ser un objeto")
        missing: list[str] = []
        observed: dict[str, str | None] = {}
        for name, expected in required.items():
            actual = response.headers.get(str(name).lower())
            observed[str(name).lower()] = actual
            if actual is None or (expected is not None and actual.lower() != str(expected).lower()):
                missing.append(str(name).lower())
        self._emit(
            check,
            "FAIL" if missing else "PASS",
            endpoint=path,
            evidence=[
                {"tipo": "cabeceras_observadas", "valor": observed},
                {"tipo": "cabeceras_ausentes_o_invalidas", "valor": missing},
            ],
            detail="faltan cabeceras requeridas" if missing else "todas las cabeceras requeridas estan presentes",
        )

    def _check_error_disclosure(self, check: dict[str, Any]) -> None:
        response, path = self._request(check)
        markers = check.get(
            "markers",
            ["Traceback (most recent call last)", "Werkzeug Debugger", "SECRET_KEY", "stack trace"],
        )
        body = response.body.decode("utf-8", errors="replace")
        matched = [str(marker) for marker in markers if str(marker).lower() in body.lower()]
        vulnerable = response.status >= 500 and bool(matched)
        self._emit(
            check,
            "FAIL" if vulnerable else "PASS",
            endpoint=path,
            evidence=[
                {"tipo": "status", "valor": response.status},
                {"tipo": "marcadores", "valor": matched},
                {"tipo": "body_sha256", "valor": response.body_sha256},
            ],
            detail="la respuesta expuso marcadores internos" if vulnerable else "no se observaron trazas internas en la respuesta",
        )

    def _check_body_limit(self, check: dict[str, Any]) -> None:
        size = int(check.get("body_size", 32_768))
        maximum = int(self.runtime.get("max_active_body_bytes", 131_072))
        if size < 1 or size > maximum:
            raise AuditError(f"body_size debe estar entre 1 y {maximum}")
        field_name = str(check.get("field") or "contenido")
        response, path = self._request(check, json_override={field_name: "A" * size})
        rejected = self._statuses(check, "rejected_status", [413])
        passed = response.status in rejected
        self._emit(
            check,
            "PASS" if passed else "FAIL",
            endpoint=path,
            evidence=[
                {"tipo": "bytes_generados", "valor": size},
                {"tipo": "status", "valor": response.status},
            ],
            detail="el cuerpo sobredimensionado fue rechazado" if passed else "el cuerpo sobredimensionado no fue rechazado por el limite esperado",
        )

    def _check_source_regex_absent(self, check: dict[str, Any]) -> None:
        files = check.get("files", [])
        patterns = check.get("patterns", [])
        if not isinstance(files, list) or not isinstance(patterns, list) or not files or not patterns:
            raise AuditError("source_regex_absent requiere files y patterns no vacios")
        matches: list[tuple[str, int, str, str]] = []
        max_bytes = int(self.config.get("max_file_bytes", 2 * 1024 * 1024))
        for relative in files:
            try:
                candidate = (self.root / str(relative)).resolve(strict=True)
            except OSError as exc:
                raise AuditError(f"archivo fuente no disponible: {relative}") from exc
            try:
                candidate.relative_to(self.root)
            except ValueError as exc:
                raise AuditError(f"ruta fuera del repositorio: {relative}") from exc
            if candidate.stat().st_size > max_bytes:
                raise AuditError(f"archivo demasiado grande para source_regex_absent: {relative}")
            text = candidate.read_text(encoding="utf-8", errors="replace")
            for pattern in patterns:
                compiled = re.compile(str(pattern), re.MULTILINE)
                for match in compiled.finditer(text):
                    line = text.count("\n", 0, match.start()) + 1
                    line_text = text.splitlines()[line - 1] if text.splitlines() else ""
                    matches.append(
                        (
                            str(relative).replace("\\", "/"),
                            line,
                            str(pattern),
                            sha256_bytes(line_text.encode("utf-8")),
                        )
                    )
        if not matches:
            self._emit(check, "PASS", detail="ningun patron prohibido fue localizado")
            return
        for relative, line, pattern, line_hash in matches:
            self._emit(
                check,
                "FAIL",
                file=relative,
                line=line,
                evidence=[
                    {"tipo": "patron", "valor": pattern},
                    {"tipo": "hash_linea", "valor": line_hash},
                ],
                detail="se encontro un patron prohibido en la configuracion fuente",
            )

    def _check_audit_hash_chain(self, check: dict[str, Any]) -> None:
        response, path = self._request(check)
        accepted = self._statuses(check, "status", [200])
        if response.status not in accepted:
            self._emit(
                check,
                "ERROR",
                endpoint=path,
                evidence=[{"tipo": "respuesta_http", "valor": response.evidence()}],
                detail="la respuesta no cumplio la precondicion HTTP",
            )
            return

        payload = response.json()
        events_path = str(check.get("events_json_path") or "$.eventos")
        events = json_path_get(payload, events_path)
        if not isinstance(events, list):
            raise AuditError("events_json_path no apunta a una lista")
        hash_field = str(check.get("hash_field") or "hash_evento")
        previous_hash_field = str(check.get("previous_hash_field") or "hash_anterior")
        trusted_anchor = str(check.get("trusted_anchor") or AUDIT_GENESIS_HASH)
        evaluation = pilar3_auditoria_sin_firma(
            events,
            hash_field=hash_field,
            previous_hash_field=previous_hash_field,
            trusted_anchor=trusted_anchor,
        )
        chain = evaluation["cadena"]
        tampered = evaluation.get("verificacion_copia_alterada") or {}
        evidence = [
            {"tipo": "respuesta_http", "valor": response.evidence()},
            {"tipo": "events_json_path", "valor": events_path},
            {"tipo": "eventos_recibidos", "valor": len(events)},
            {"tipo": "campos_requeridos", "valor": [previous_hash_field, hash_field]},
            {"tipo": "cadena_valida", "valor": chain["valida"]},
            {"tipo": "eventos_verificados", "valor": chain["eventos_verificados"]},
            {"tipo": "primer_indice_invalido", "valor": chain["primer_indice_invalido"]},
            {"tipo": "razon_invalidez", "valor": chain["razon"]},
            {
                "tipo": "alteracion_controlada_detectada",
                "valor": evaluation["alteracion_controlada_detectada"],
            },
            {
                "tipo": "indice_detectado_en_copia_alterada",
                "valor": tampered.get("primer_indice_invalido"),
            },
        ]
        vulnerable = bool(evaluation["vulnerable"])
        self._emit(
            check,
            "FAIL" if vulnerable else "PASS",
            endpoint=path,
            evidence=evidence,
            detail=(
                "el registro no tiene una cadena valida y verificable"
                if vulnerable
                else "la cadena es valida y detecta una alteracion controlada en memoria"
            ),
        )


class RuleEngine:
    def __init__(
        self,
        reader: RepositoryReader,
        parsers: ParserRegistry,
        config: dict[str, Any],
        run: dict[str, Any],
    ) -> None:
        self.reader = reader
        self.parsers = parsers
        self.config = config
        self.run = run
        self.events: list[dict[str, Any]] = []
        self.findings: list[dict[str, Any]] = []
        self._finding_keys: set[tuple[Any, ...]] = set()

    def execute(self) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        self._versions()
        self._lockfiles()
        self._lock_consistency()
        self._advisories()
        self._maintenance()
        self._provenance()
        self._trusted_sources()
        self._immutable_git_refs()
        self._expected_hash_presence()
        self._expected_hash_match()
        self._ci_download_integrity()
        return self.events, self.findings

    def _emit(
        self,
        rule_id: str,
        result: str,
        *,
        component: Component | None = None,
        file: str | None = None,
        line: int | None = None,
        json_path: str | None = None,
        evidence: list[dict[str, Any]] | None = None,
        detail: str | None = None,
        confidence: str = "ALTA",
        title: str | None = None,
        severity: str | None = None,
    ) -> None:
        if result not in RULE_RESULTS:
            raise AuditError(f"resultado de regla invalido: {result}")
        rule = RULES[rule_id]
        target_file = file or (component.manifest if component else None)
        target_line = line if line is not None else (component.line if component else None)
        target_path = json_path if json_path is not None else (component.json_path if component else None)
        event = {
            "pilar": 3,
            "regla_id": rule_id,
            "resultado": result,
            "archivo": target_file,
            "ubicacion": {
                "linea_inicio": target_line,
                "linea_fin": target_line,
                "json_path": target_path,
            },
            "componente": component.name if component else None,
            "detalle": detail,
            "evidencia": evidence or [],
        }
        self.events.append(event)
        if result not in {"FAIL", "ERROR"}:
            return
        final_state = "CONFIRMADO" if result == "FAIL" else "REQUIERE_REVISION"
        finding_key = (
            rule_id,
            target_file,
            target_line,
            target_path,
            component.key if component else None,
            detail,
        )
        if finding_key in self._finding_keys:
            return
        self._finding_keys.add(finding_key)
        source = component.source if component else None
        finding = {
            "pilar": 3,
            "corrida_id": self.run["corrida_id"],
            "timestamp_utc": self.run["timestamp_utc"],
            "condicion": self.run["condicion"],
            "modo_control": self.run["modo_control"],
            "repo_hash": self.run["repo_hash"],
            "caso_id": self.config.get("case_id") or self.reader.root.name,
            "archivo": target_file,
            "ubicacion": event["ubicacion"],
            "tipo_archivo": classify_file(target_file) if target_file else None,
            "componente": component.name if component else None,
            "ecosistema": component.ecosystem if component else None,
            "version": (
                component.resolved_version or component.declared_version
                if component
                else None
            ),
            "categoria_owasp": rule["category"],
            "regla_id": rule_id,
            "hallazgo": title or rule["title"],
            "severidad": severity or rule["severity"],
            "detalle": detail,
            "evidencia": evidence or [],
            "origen_procedencia": {
                "valor": redact_url(source) if source else None,
                "verificable": bool(source),
            },
            "resultado_determinista": {"ejecutada": True, "resultado": result},
            "confianza": confidence,
            "recomendacion": rule["recommendation"],
            "estado_final": final_state,
        }
        if finding["estado_final"] not in FINAL_STATES:
            raise AuditError("estado final invalido")
        self.findings.append(finding)

    def _versions(self) -> None:
        applicable = [
            component
            for component in self.parsers.components
            if component.direct
            and component.ecosystem not in {"github-actions"}
            and not component.metadata.get("direct_reference")
            and not (component.source or "").startswith("local:")
        ]
        if not applicable:
            self._emit("R-A03-001", "SKIP_JUSTIFICADO", detail="sin componentes aplicables")
            return
        for component in applicable:
            fixed = exact_version(component.ecosystem, component.declared_version)
            evidence = [
                {
                    "tipo": "especificador",
                    "valor": component.declared_version,
                    "fuente": component.metadata.get("raw"),
                }
            ]
            self._emit(
                "R-A03-001",
                "PASS" if fixed else "FAIL",
                component=component,
                evidence=evidence,
                detail=(
                    "la version cumple la politica exacta"
                    if fixed
                    else "el especificador no identifica una version exacta e inmutable"
                ),
            )

    def _lockfiles(self) -> None:
        if not self.config.get("require_lockfiles", True):
            self._emit("R-A03-002", "SKIP_JUSTIFICADO", detail="politica desactivada")
            return
        records = {record.path: record for record in self.reader.records}
        record_names = {PurePosixPath(path).name.lower() for path in records}
        manifests = [record for record in self.reader.records if record.kind in {
            "python_requirements", "python_pyproject", "npm_manifest", "cargo_manifest", "go_manifest", "gradle_manifest"
        }]
        seen = False
        for manifest in manifests:
            name = PurePosixPath(manifest.path).name.lower()
            if manifest.kind == "python_requirements" and "lock" in name:
                continue
            seen = True
            expected: list[str]
            present = False
            if manifest.kind == "python_requirements":
                expected = ["requirements.lock", "requirements.lock.txt", "poetry.lock", "pdm.lock", "uv.lock", "pipfile.lock"]
                related = [c for c in self.parsers.components if c.manifest == manifest.path and c.direct]
                hashed_lock = bool(related) and all(
                    c.resolved_version and c.metadata.get("hashes") for c in related
                )
                present = any(item in record_names for item in expected) or bool(
                    self.config.get("requirements_hashes_satisfy_lock") and hashed_lock
                )
            elif manifest.kind == "python_pyproject":
                expected = ["poetry.lock", "pdm.lock", "uv.lock", "pipfile.lock", "requirements.lock"]
                present = any(item in record_names for item in expected)
            elif manifest.kind == "npm_manifest":
                expected = ["package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"]
                present = any(item in record_names for item in expected)
            elif manifest.kind == "cargo_manifest":
                expected = ["cargo.lock"]
                present = "cargo.lock" in record_names
            elif manifest.kind == "go_manifest":
                expected = ["go.sum"]
                present = "go.sum" in record_names
            else:
                expected = ["gradle.lockfile", "gradle/dependency-locks/"]
                present = "gradle.lockfile" in record_names or any(
                    "dependency-locks/" in path.lower() for path in records
                )
            self._emit(
                "R-A03-002",
                "PASS" if present else "FAIL",
                file=manifest.path,
                evidence=[{"tipo": "lockfiles_esperados", "valor": expected}],
                detail="lockfile localizado" if present else "ningun lockfile esperado fue inventariado",
            )
        if not seen:
            self._emit("R-A03-002", "SKIP_JUSTIFICADO", detail="sin manifests que requieran lockfile")

    def _lock_for(self, component: Component) -> tuple[str | None, dict[tuple[str, str], str] | None]:
        choices: list[str] = []
        if component.ecosystem == "pypi":
            choices = ["requirements.lock", "requirements.lock.txt", "poetry.lock", "pdm.lock", "uv.lock", "pipfile.lock"]
        elif component.ecosystem == "npm":
            choices = ["package-lock.json", "npm-shrinkwrap.json"]
        elif component.ecosystem == "cargo":
            choices = ["cargo.lock"]
        elif component.ecosystem == "go":
            choices = ["go.sum"]
        for path, resolved in self.parsers.resolved.items():
            if PurePosixPath(path).name.lower() in choices:
                return path, resolved
        return None, None

    def _lock_consistency(self) -> None:
        checked = False
        for component in self.parsers.components:
            if not component.direct or component.ecosystem not in {"pypi", "npm", "cargo", "go"}:
                continue
            lock_path, resolved = self._lock_for(component)
            if not lock_path or resolved is None:
                continue
            checked = True
            locked = resolved.get(component.key)
            if locked is None:
                self._emit(
                    "R-A03-003",
                    "FAIL",
                    component=component,
                    evidence=[{"tipo": "lockfile", "valor": lock_path}],
                    detail="la dependencia directa no aparece resuelta en el lockfile soportado",
                )
            else:
                self._emit(
                    "R-A03-003",
                    "PASS",
                    component=component,
                    evidence=[{"tipo": "version_resuelta", "valor": locked, "lockfile": lock_path}],
                    detail="la dependencia aparece en el lockfile",
                )
        if not checked:
            self._emit(
                "R-A03-003",
                "SKIP_JUSTIFICADO",
                detail="no hay un par manifest-lock soportado para comparar",
            )

    def _matching_advisories(self, component: Component) -> list[dict[str, Any]]:
        version = component.resolved_version
        if not version and component.declared_version and exact_version(component.ecosystem, component.declared_version):
            version = component.declared_version.lstrip("=v ")
        if not version:
            return []
        matches = []
        for advisory in self.config.get("advisories", []):
            if not isinstance(advisory, dict):
                continue
            if str(advisory.get("ecosystem", "")).lower() != component.ecosystem.lower():
                continue
            if normalized_name(component.ecosystem, str(advisory.get("component", ""))) != component.key[1]:
                continue
            if str(advisory.get("version", "")) == version:
                matches.append(advisory)
        return matches

    def _advisories(self) -> None:
        if not self.config.get("advisories"):
            self._emit("R-A03-004", "SKIP_JUSTIFICADO", detail="catalogo local vacio")
            return
        for component in self.parsers.components:
            if not component.direct:
                continue
            for advisory in self._matching_advisories(component):
                if str(advisory.get("status", "vulnerable")).lower() not in {"vulnerable", "affected"}:
                    continue
                self._emit(
                    "R-A03-004",
                    "FAIL",
                    component=component,
                    evidence=[
                        {"tipo": "advisory_id", "valor": advisory.get("advisory_id")},
                        {"tipo": "coincidencia_exacta", "valor": advisory.get("version")},
                    ],
                    detail=str(advisory.get("summary") or "coincidencia exacta en dataset local"),
                    severity=str(advisory.get("severity") or RULES["R-A03-004"]["severity"]).upper(),
                )

    def _maintenance(self) -> None:
        candidates = [
            (component, advisory)
            for component in self.parsers.components
            if component.direct
            for advisory in self._matching_advisories(component)
            if str(advisory.get("maintenance", "")).lower() in {"unmaintained", "eol", "sin_mantenimiento"}
        ]
        if not candidates:
            self._emit("R-A03-005", "SKIP_JUSTIFICADO", detail="sin coincidencias de mantenimiento en el dataset")
            return
        for component, advisory in candidates:
            self._emit(
                "R-A03-005",
                "FAIL",
                component=component,
                evidence=[
                    {"tipo": "estado_mantenimiento", "valor": advisory.get("maintenance")},
                    {"tipo": "fecha_corte", "valor": advisory.get("cutoff_date")},
                ],
                detail="el dataset local marca el componente como no mantenido",
            )

    def _provenance(self) -> None:
        applicable = [component for component in self.parsers.components if component.direct]
        if not applicable:
            self._emit("R-A03-006", "SKIP_JUSTIFICADO", detail="sin componentes")
            return
        explicit = bool(self.config.get("require_explicit_provenance"))
        for component in applicable:
            source = component.source
            implicit_registry = bool(source and source.startswith("registry:"))
            valid = bool(source) and not (explicit and implicit_registry)
            self._emit(
                "R-A03-006",
                "PASS" if valid else "FAIL",
                component=component,
                evidence=[{"tipo": "origen", "valor": source}],
                detail=(
                    "la fuente esta declarada o normalizada por el ecosistema"
                    if valid
                    else "la politica exige procedencia explicita y no existe evidencia suficiente"
                ),
            )

    def _trusted_sources(self) -> None:
        candidates: list[tuple[str, str, int | None, Component | None]] = []
        for component in self.parsers.components:
            host = source_host(component.source)
            if host:
                candidates.append((host, component.manifest, component.line, component))
        for item in self.parsers.sources:
            host = source_host(item.get("fuente"))
            if host:
                candidates.append((host, item["archivo"], item.get("linea"), None))
        if not candidates:
            self._emit("R-A03-007", "SKIP_JUSTIFICADO", detail="sin fuentes de red detectadas")
            return
        allowed = self.config["allowed_source_hosts"]
        for host, file, line, component in candidates:
            accepted = host_allowed(host, allowed)
            self._emit(
                "R-A03-007",
                "PASS" if accepted else "FAIL",
                component=component,
                file=file,
                line=line,
                evidence=[
                    {"tipo": "host_normalizado", "valor": host},
                    {"tipo": "permitido", "valor": accepted},
                ],
                detail="fuente incluida en allowlist" if accepted else "host ausente de allowed_source_hosts",
            )

    def _immutable_git_refs(self) -> None:
        candidates = [
            component
            for component in self.parsers.components
            if component.ecosystem == "github-actions"
            or component.metadata.get("git_ref") is not None
            or (component.source and "git" in component.source.lower())
        ]
        if not candidates:
            self._emit("R-A03-008", "SKIP_JUSTIFICADO", detail="sin referencias Git")
            return
        for component in candidates:
            ref = component.metadata.get("git_ref") or extract_git_ref(component.source or "")
            immutable = is_full_commit(str(ref)) if ref else False
            self._emit(
                "R-A03-008",
                "PASS" if immutable else "FAIL",
                component=component,
                evidence=[{"tipo": "referencia_git", "valor": ref}],
                detail="commit completo e inmutable" if immutable else "la referencia no es un commit completo de 40 a 64 hexadecimales",
            )

    def _matches_integrity_glob(self, path: str) -> bool:
        return any(
            fnmatch.fnmatch(path, pattern) or PurePosixPath(path).match(pattern)
            for pattern in self.config.get("integrity_required_globs", [])
        )

    def _expected_hash_presence(self) -> None:
        applicable = False
        if self.config.get("require_python_hashes"):
            for component in self.parsers.components:
                if component.ecosystem != "pypi" or not component.direct:
                    continue
                if classify_file(component.manifest) != "python_requirements":
                    continue
                applicable = True
                hashes = component.metadata.get("hashes") or []
                self._emit(
                    "R-A08-001",
                    "PASS" if hashes else "FAIL",
                    component=component,
                    evidence=[{"tipo": "hashes_declarados", "valor": hashes}],
                    detail="hash SHA-256 declarado" if hashes else "la dependencia de requirements no declara --hash=sha256",
                )
        expected = self.config.get("expected_hashes", {})
        for record in self.reader.records:
            if not self._matches_integrity_glob(record.path):
                continue
            applicable = True
            present = record.path in expected
            self._emit(
                "R-A08-001",
                "PASS" if present else "FAIL",
                file=record.path,
                evidence=[{"tipo": "entrada_expected_hashes", "valor": expected.get(record.path)}],
                detail="hash esperado registrado" if present else "artefacto sujeto a politica sin hash esperado",
            )
        if not applicable:
            self._emit("R-A08-001", "SKIP_JUSTIFICADO", detail="sin dependencias o artefactos sujetos a hashes")

    def _expected_hash_match(self) -> None:
        expected = self.config.get("expected_hashes", {})
        if not expected:
            self._emit("R-A08-002", "SKIP_JUSTIFICADO", detail="expected_hashes vacio")
            return
        by_path = {record.path: record for record in self.reader.records}
        for path, expected_digest in sorted(expected.items()):
            normalized = expected_digest.lower()
            if not normalized.startswith("sha256:"):
                normalized = "sha256:" + normalized
            record = by_path.get(path)
            actual = record.sha256.lower() if record else None
            matches = bool(actual and actual == normalized)
            self._emit(
                "R-A08-002",
                "PASS" if matches else "FAIL",
                file=path,
                evidence=[
                    {"tipo": "sha256_esperado", "valor": normalized},
                    {"tipo": "sha256_calculado", "valor": actual},
                ],
                detail=(
                    "el hash coincide"
                    if matches
                    else "el archivo falta o su SHA-256 no coincide con el valor esperado"
                ),
            )

    def _ci_download_integrity(self) -> None:
        verify = re.compile(
            r"\b(sha256sum|shasum\s+-a\s+256|Get-FileHash|certutil\s+-hashfile|cosign|gpg\s+--verify)\b",
            re.IGNORECASE,
        )
        found = False
        window_size = int(self.config.get("ci_verification_window", 8))
        for record in self.reader.records:
            if record.kind != "ci_pipeline" or not record.readable:
                continue
            lines = self.reader.text(record.path).splitlines()
            for index, raw in enumerate(lines):
                curl_download = bool(
                    re.search(r"\bcurl\b", raw, re.I)
                    and (
                        re.search(r"(?:^|\s)(?:-o|-O|--output)(?:=|\s)", raw)
                        or re.search(r"\|\s*(?:sh|bash)\b", raw, re.I)
                        or re.search(r">\s*[^&\s]", raw)
                    )
                )
                if curl_download and (
                    re.search(r"https?://(?:127\.0\.0\.1|localhost|\[::1\])(?::\d+)?", raw, re.I)
                    or re.search(r">\s*(?:/dev/null|\$null|nul)(?:\s|$)", raw, re.I)
                ) and not re.search(r"\|\s*(?:sh|bash)\b", raw, re.I):
                    curl_download = False
                wget_download = bool(
                    re.search(r"\bwget\b", raw, re.I)
                    and not re.search(r"\bwget\b[^\n]*--spider\b", raw, re.I)
                )
                powershell_download = bool(
                    re.search(r"\bStart-BitsTransfer\b", raw, re.I)
                    or (
                        re.search(r"\b(?:Invoke-WebRequest|iwr)\b", raw, re.I)
                        and re.search(r"\b(?:-OutFile|Invoke-Expression|iex)\b", raw, re.I)
                    )
                )
                if not (curl_download or wget_download or powershell_download):
                    continue
                found = True
                window = "\n".join(lines[index : index + window_size + 1])
                verified = bool(verify.search(window))
                self._emit(
                    "R-A08-003",
                    "PASS" if verified else "FAIL",
                    file=record.path,
                    line=index + 1,
                    evidence=[
                        {"tipo": "linea_descarga", "valor": raw.strip()},
                        {"tipo": "ventana_verificacion", "valor": window_size},
                    ],
                    detail=(
                        "se encontro una verificacion de integridad cercana"
                        if verified
                        else "no se encontro hash o firma en la ventana posterior definida por la politica"
                    ),
                    confidence="MEDIA" if not verified else "ALTA",
                )
        if not found:
            self._emit("R-A08-003", "SKIP_JUSTIFICADO", detail="sin descargas directas en CI/CD")


def summarize(
    events: list[dict[str, Any]], findings: list[dict[str, Any]]
) -> dict[str, Any]:
    by_state = {state: 0 for state in sorted(FINAL_STATES)}
    by_severity = {severity: 0 for severity in SEVERITY_ORDER}
    by_rule: dict[str, dict[str, int]] = {}
    for event in events:
        counts = by_rule.setdefault(
            event["regla_id"], {result: 0 for result in sorted(RULE_RESULTS)}
        )
        counts[event["resultado"]] += 1
    for finding in findings:
        by_state[finding["estado_final"]] += 1
        by_severity[finding["severidad"]] = by_severity.get(finding["severidad"], 0) + 1
    return {
        "hallazgos_total": len(findings),
        "por_estado": by_state,
        "por_severidad": by_severity,
        "eventos_por_regla": by_rule,
    }


def summarize_by_pillar(
    events: list[dict[str, Any]], findings: list[dict[str, Any]]
) -> dict[str, Any]:
    pillars = sorted(
        {int(item["pilar"]) for item in events + findings if item.get("pilar") is not None}
    )
    return {
        str(pillar): summarize(
            [item for item in events if int(item.get("pilar", 0)) == pillar],
            [item for item in findings if int(item.get("pilar", 0)) == pillar],
        )
        for pillar in pillars
    }


def compare_evidence_reports(
    first: dict[str, Any], second: dict[str, Any]
) -> dict[str, Any]:
    """Compara dos corridas A/B sin confundir cambios del sistema con el instrumento."""

    reports = {
        str(first.get("corrida", {}).get("condicion")): first,
        str(second.get("corrida", {}).get("condicion")): second,
    }
    if set(reports) != {CONDITION_BASELINE, CONDITION_CONTROL}:
        raise AuditError("la comparacion requiere exactamente una corrida A y una corrida B")
    baseline = reports[CONDITION_BASELINE]
    intervention = reports[CONDITION_CONTROL]

    def rule_results(report: dict[str, Any]) -> dict[str, dict[str, int]]:
        return {
            str(rule_id): {str(key): int(value) for key, value in counts.items()}
            for rule_id, counts in report.get("resumen", {})
            .get("eventos_por_regla", {})
            .items()
        }

    baseline_rules = rule_results(baseline)
    intervention_rules = rule_results(intervention)
    all_rules = sorted(set(baseline_rules) | set(intervention_rules))
    changes = {
        rule_id: {
            "A": baseline_rules.get(rule_id, {}),
            "B": intervention_rules.get(rule_id, {}),
            "cambio": baseline_rules.get(rule_id, {})
            != intervention_rules.get(rule_id, {}),
        }
        for rule_id in all_rules
    }

    baseline_tool_hash = baseline.get("tool", {}).get("sha256")
    intervention_tool_hash = intervention.get("tool", {}).get("sha256")
    baseline_policy_hash = (
        baseline.get("corrida", {}).get("config_hashes", {}).get("effective_config")
    )
    intervention_policy_hash = (
        intervention.get("corrida", {}).get("config_hashes", {}).get("effective_config")
    )
    return {
        "condicion_inicial_id": baseline.get("corrida", {}).get("corrida_id"),
        "intervencion_id": intervention.get("corrida", {}).get("corrida_id"),
        "instrumento_identico": bool(
            baseline_tool_hash
            and baseline_tool_hash == intervention_tool_hash
        ),
        "politica_identica": bool(
            baseline_policy_hash
            and baseline_policy_hash == intervention_policy_hash
        ),
        "repositorio_cambio": (
            baseline.get("corrida", {}).get("repo_hash")
            != intervention.get("corrida", {}).get("repo_hash")
        ),
        "hallazgos": {
            "A": int(baseline.get("resumen", {}).get("hallazgos_total", 0)),
            "B": int(intervention.get("resumen", {}).get("hallazgos_total", 0)),
        },
        "cambios_por_regla": changes,
        "reglas_con_cambio": [
            rule_id for rule_id, detail in changes.items() if detail["cambio"]
        ],
    }


def analizar_repositorio(
    ruta_repositorio: str | Path,
    modo_control: bool = True,
    catalogo_owasp: dict[str, Any] | str | Path | None = None,
    configuracion: dict[str, Any] | str | Path | None = None,
    *,
    excluded_paths: Iterable[Path] = (),
) -> dict[str, Any]:
    """Analiza un repositorio sin red, sin ejecucion y sin modificarlo.

    Las condiciones A y B ejecutan exactamente las mismas reglas. ``modo_control``
    solo etiqueta si la copia corresponde a la linea base o a la intervencion;
    el efecto se observa comparando los resultados de ambas corridas.
    """

    started_monotonic = time.monotonic()
    started = utc_now()
    config, config_hashes = load_config(configuracion)
    catalog_hash = None
    if catalogo_owasp is not None:
        if isinstance(catalogo_owasp, (str, Path)):
            catalog_path = Path(catalogo_owasp).expanduser().resolve(strict=True)
            _load_json(catalog_path)
            catalog_hash = sha256_file(catalog_path)
        elif isinstance(catalogo_owasp, dict):
            catalog_hash = sha256_bytes(canonical_json(catalogo_owasp))
        else:
            raise AuditError("catalogo_owasp debe ser objeto, ruta o None")

    reader = RepositoryReader(Path(ruta_repositorio), config, excluded_paths)
    records = reader.inventory()
    repo_hash = reader.tree_hash()
    parsers = ParserRegistry(reader)
    components = parsers.parse()
    run = {
        "corrida_id": str(uuid.uuid4()),
        "timestamp_utc": started,
        "condicion": CONDITION_CONTROL if modo_control else CONDITION_BASELINE,
        "modo_control": bool(modo_control),
        "repo_hash": repo_hash,
    }

    events, findings = RuleEngine(reader, parsers, config, run).execute()

    findings.sort(
        key=lambda item: (
            -SEVERITY_ORDER.get(item["severidad"], 0),
            item["regla_id"],
            item.get("archivo") or "",
            item.get("componente") or "",
        )
    )
    limitations: list[str] = []
    if reader.skipped_symlinks:
        limitations.append(
            "Se omitieron enlaces simbolicos: " + ", ".join(reader.skipped_symlinks)
        )
    if reader.skipped_large:
        limitations.append(
            "No se parsearon archivos mayores que max_file_bytes: "
            + ", ".join(reader.skipped_large)
        )
    if parsers.unsupported:
        limitations.append(
            "Artefactos detectados sin parser completo: " + ", ".join(sorted(set(parsers.unsupported)))
        )
    if parsers.parse_errors:
        limitations.append(
            "Existieron errores de parsing; no interprete la ausencia de hallazgos como ausencia de riesgo."
        )
    limitations.append(
        "El analisis es estatico y offline: no consulta vulnerabilidades publicas ni prueba explotabilidad."
    )

    duration = round(time.monotonic() - started_monotonic, 6)
    report = {
        "schema_version": SCHEMA_VERSION,
        "tool": {
            "name": "auditor_tramitia",
            "version": TOOL_VERSION,
            "sha256": sha256_file(Path(__file__).resolve()),
            "pillar": "Pilar 3 - Integridad y cadena de suministro",
            "network_used": False,
            "repository_executed": False,
            "repository_modified": False,
            "application_state_may_change": False,
        },
        "corrida": {
            **run,
            "finalizada_utc": utc_now(),
            "duracion_segundos": duration,
            "config_hashes": config_hashes,
            "catalogo_owasp_hash": catalog_hash,
            "reglas_activas": sorted(RULES),
        },
        "alcance": {
            "repositorio": str(reader.root),
            "archivos_inventariados": len(records),
            "bytes_inventariados": sum(item.size for item in records),
            "enlaces_simbolicos_omitidos": reader.skipped_symlinks,
            "archivos_grandes_no_parseados": reader.skipped_large,
        },
        "inventario_archivos": [asdict(record) for record in records],
        "componentes": [component.as_public_dict() for component in components],
        "resultados_reglas": events,
        "hallazgos": findings,
        "resumen": summarize(events, findings),
        "errores_parsing": parsers.parse_errors,
        "limitaciones": limitations,
        "diseno_comparativo": {
            "condicion": run["condicion"],
            "instrumento_identico_en_a_y_b": True,
            "instrumento_sha256": sha256_file(Path(__file__).resolve()),
            "politica_efectiva_sha256": config_hashes["effective_config"],
            "interpretacion": (
                "A identifica la copia inicial sin intervencion; B identifica la copia "
                "con la intervencion. Las mismas reglas se ejecutan en ambas."
            ),
        },
    }
    return redact_sensitive(report)


def auditar_aplicacion(
    ruta_repositorio: str | Path,
    *,
    pilares: Iterable[int] = (1, 2, 3),
    base_url: str | None = None,
    modo_control: bool = True,
    catalogo_owasp: dict[str, Any] | str | Path | None = None,
    configuracion: dict[str, Any] | str | Path | None = None,
    excluded_paths: Iterable[Path] = (),
    active_tests_authorized: bool = False,
    allow_non_loopback: bool = False,
    runtime_client: Any | None = None,
) -> dict[str, Any]:
    """Ejecuta una corrida unificada de los pilares seleccionados.

    Los pilares 1 y 2 usan los controles declarados en ``runtime.checks``. El
    Pilar 3 usa el motor estatico incorporado y, cuando esta declarado, el
    control runtime de integridad del registro.
    """

    started = time.monotonic()
    selected = {int(pillar) for pillar in pilares}
    if not selected or not selected.issubset({1, 2, 3}):
        raise AuditError("pilares debe contener uno o mas valores entre 1 y 3")
    effective_config, _ = load_config(configuracion)
    report = analizar_repositorio(
        ruta_repositorio,
        modo_control=modo_control,
        catalogo_owasp=catalogo_owasp,
        configuracion=configuracion,
        excluded_paths=excluded_paths,
    )
    if 3 not in selected:
        report["resultados_reglas"] = []
        report["hallazgos"] = []

    runtime_checks = effective_config.get("runtime", {}).get("checks", [])
    declared = {
        int(check.get("pillar", 0))
        for check in runtime_checks
        if isinstance(check, dict)
    }
    required_runtime_pillars = selected & {1, 2}
    missing = required_runtime_pillars - declared
    if missing:
        raise AuditError(
            "no hay controles runtime configurados para los pilares: "
            + ", ".join(str(item) for item in sorted(missing))
        )
    runtime_pillars = required_runtime_pillars | (selected & declared & {3})
    selected_active_checks = [
        str(check.get("id"))
        for check in runtime_checks
        if isinstance(check, dict)
        and int(check.get("pillar", 0)) in runtime_pillars
        and bool(check.get("active"))
    ]
    if runtime_pillars:
        network_types = RuntimeAuditor.SUPPORTED_TYPES - {"source_regex_absent"}
        needs_network = any(
            isinstance(check, dict)
            and int(check.get("pillar", 0)) in runtime_pillars
            and check.get("type") in network_types
            for check in runtime_checks
        )
        client = runtime_client
        configured_url = base_url or effective_config.get("runtime", {}).get("base_url")
        if client is None and needs_network:
            if not configured_url:
                raise AuditError("los controles runtime configurados requieren --base-url")
            runtime_options = effective_config.get("runtime", {})
            client = HttpClient(
                str(configured_url),
                timeout=float(runtime_options.get("timeout_seconds", 5)),
                max_requests=int(runtime_options.get("max_requests", 50)),
                max_response_bytes=int(runtime_options.get("max_response_bytes", 262_144)),
                allow_non_loopback=allow_non_loopback,
            )
        runtime_events, runtime_findings = RuntimeAuditor(
            Path(ruta_repositorio),
            effective_config,
            report["corrida"],
            client,
            selected_pillars=runtime_pillars,
            active_tests_authorized=active_tests_authorized,
        ).execute()
        report["resultados_reglas"].extend(runtime_events)
        report["hallazgos"].extend(runtime_findings)
        report["runtime"] = {
            "base_url": getattr(client, "base_url", configured_url),
            "peticiones_realizadas": getattr(client, "request_count", None),
            "pruebas_activas_autorizadas": active_tests_authorized,
            "controles_activos_declarados": selected_active_checks,
            "red_no_loopback_autorizada": allow_non_loopback,
        }
    else:
        report["runtime"] = {
            "base_url": None,
            "peticiones_realizadas": 0,
            "pruebas_activas_autorizadas": False,
            "controles_activos_declarados": [],
            "red_no_loopback_autorizada": False,
        }

    report["hallazgos"].sort(
        key=lambda item: (
            int(item.get("pilar", 0)),
            -SEVERITY_ORDER.get(item.get("severidad", "INFORMATIVA"), 0),
            item.get("regla_id") or "",
            item.get("archivo") or item.get("endpoint") or "",
        )
    )
    report["resumen"] = summarize(report["resultados_reglas"], report["hallazgos"])
    report["resumen_por_pilar"] = summarize_by_pillar(
        report["resultados_reglas"], report["hallazgos"]
    )
    report["corrida"]["pilares_solicitados"] = sorted(selected)
    report["corrida"]["pilares_ejecutados"] = sorted(
        {
            int(item["pilar"])
            for item in report["resultados_reglas"]
            if item.get("pilar") in selected
        }
    )
    report["corrida"]["finalizada_utc"] = utc_now()
    report["corrida"]["duracion_segundos"] = round(time.monotonic() - started, 6)
    report["tool"]["pillar"] = "Pilares 1, 2 y 3"
    report["tool"]["network_used"] = bool(
        report["runtime"].get("peticiones_realizadas")
    )
    report["tool"]["application_state_may_change"] = bool(
        active_tests_authorized and selected_active_checks
    )
    return redact_sensitive(report)


def write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    path = path.expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", dir=path.parent, delete=False, suffix=".tmp"
        ) as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            temporary_name = handle.name
        Path(temporary_name).replace(path)
    finally:
        if temporary_name:
            temporary = Path(temporary_name)
            if temporary.exists():
                temporary.unlink()


def print_summary(
    report: dict[str, Any], output: Path, document_output: Path | None = None
) -> None:
    summary = report["resumen"]
    pillars = report["corrida"].get("pilares_ejecutados", [3])
    print("Auditoria completada para los pilares " + ", ".join(map(str, pillars)))
    print(f"Repositorio: {report['alcance']['repositorio']}")
    print(f"Hash del arbol: {report['corrida']['repo_hash']}")
    print(
        "Inventario: "
        f"{report['alcance']['archivos_inventariados']} archivos, "
        f"{len(report['componentes'])} componentes"
    )
    print(f"Hallazgos: {summary['hallazgos_total']}")
    for severity in ("CRITICA", "ALTA", "MEDIA", "BAJA", "INFORMATIVA"):
        count = summary["por_severidad"].get(severity, 0)
        if count:
            print(f"  {severity}: {count}")
    for finding in report["hallazgos"]:
        location = finding.get("archivo") or "repositorio"
        line = finding.get("ubicacion", {}).get("linea_inicio")
        if line:
            location += f":{line}"
        component = f" [{finding['componente']}]" if finding.get("componente") else ""
        print(
            f"- P{finding.get('pilar', '?')} {finding['severidad']} "
            f"{finding['regla_id']} {location}{component}: "
            f"{finding['hallazgo']}"
        )
    if report.get("runtime", {}).get("peticiones_realizadas") is not None:
        print(f"Peticiones HTTP: {report['runtime']['peticiones_realizadas']}")
    print(f"Evidencia JSON: {output}")
    if document_output is not None:
        print(f"Informe DOCX: {document_output}")


def _should_fail(report: dict[str, Any], threshold: str | None) -> bool:
    if not threshold:
        return False
    minimum = SEVERITY_ORDER[threshold]
    return any(
        finding["estado_final"] == "CONFIRMADO"
        and SEVERITY_ORDER.get(finding["severidad"], 0) >= minimum
        for finding in report["hallazgos"]
    )


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Audita los pilares 1 y 2 mediante controles HTTP declarativos y el "
            "Pilar 3 mediante analisis estatico y verificacion del registro."
        )
    )
    parser.add_argument("--repo", required=True, help="copia local autorizada del repositorio")
    parser.add_argument(
        "--out",
        default="evidencia_auditoria.json",
        help="archivo JSON de evidencia",
    )
    parser.add_argument(
        "--out-docx",
        help=(
            "informe DOCX opcional generado desde el mismo JSON; requiere "
            "python-docx"
        ),
    )
    parser.add_argument(
        "--config",
        help=(
            "politica JSON; al seleccionar pilares 1/2 se usa "
            "auditor_config.tramitia.example.json si existe junto al script"
        ),
    )
    parser.add_argument("--catalogo-owasp", help="catalogo OWASP local opcional; se registra su hash")
    parser.add_argument(
        "--pilares",
        default="1,2,3",
        help="pilares separados por coma; el valor predeterminado es 1,2,3",
    )
    parser.add_argument(
        "--base-url",
        help="instancia autorizada para los controles HTTP de los tres pilares",
    )
    parser.add_argument(
        "--condicion",
        choices=(CONDITION_BASELINE, CONDITION_CONTROL),
        default=CONDITION_CONTROL,
        help=(
            "A etiqueta la copia inicial y B la copia intervenida; ambas ejecutan "
            "exactamente las mismas pruebas"
        ),
    )
    parser.add_argument(
        "--autorizado",
        "--confirm-authorized",
        action="store_true",
        help="confirma que el repositorio esta autorizado y es una copia de analisis",
    )
    parser.add_argument(
        "--permitir-pruebas-activas",
        action="store_true",
        help="autoriza controles acotados repetitivos o con cuerpos de prueba",
    )
    parser.add_argument(
        "--permitir-red",
        action="store_true",
        help="permite una base_url distinta de localhost; usar solo dentro del alcance autorizado",
    )
    parser.add_argument(
        "--fail-on",
        choices=tuple(SEVERITY_ORDER),
        help="devuelve codigo 2 si hay un hallazgo confirmado de esta severidad o mayor",
    )
    parser.add_argument(
        "--comparar-con",
        help=(
            "evidencia JSON de la otra condicion; agrega una comparacion A/B "
            "al informe actual"
        ),
    )
    parser.add_argument("--quiet", action="store_true", help="no imprime el resumen en consola")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_argument_parser()
    args = parser.parse_args(argv)
    if not args.autorizado:
        parser.error(
            "falta --autorizado: confirme que tiene permiso y que analiza una copia local"
        )
    output = Path(args.out)
    document_output = Path(args.out_docx) if args.out_docx else None
    try:
        try:
            pillars = {int(item.strip()) for item in args.pilares.split(",") if item.strip()}
        except ValueError as exc:
            raise AuditError("--pilares debe usar numeros separados por coma") from exc
        comparison_input = None
        if args.comparar_con:
            try:
                comparison_input = Path(args.comparar_con).expanduser().resolve(strict=True)
            except OSError as exc:
                raise AuditError(f"no se pudo resolver --comparar-con: {exc}") from exc
        excluded_outputs = tuple(
            path
            for path in (output, document_output, comparison_input)
            if path is not None
        )
        configuration = args.config
        if configuration is None and pillars & {1, 2}:
            project_config = Path(__file__).with_name(
                "auditor_config.tramitia.example.json"
            )
            if project_config.is_file():
                configuration = project_config
        report = auditar_aplicacion(
            args.repo,
            pilares=pillars,
            base_url=args.base_url,
            modo_control=args.condicion == CONDITION_CONTROL,
            catalogo_owasp=args.catalogo_owasp,
            configuracion=configuration,
            excluded_paths=excluded_outputs,
            active_tests_authorized=args.permitir_pruebas_activas,
            allow_non_loopback=args.permitir_red,
        )
        if comparison_input is not None:
            other = _load_json(comparison_input)
            if not isinstance(other, dict):
                raise AuditError("--comparar-con debe contener un informe JSON")
            report["comparacion_ab"] = compare_evidence_reports(other, report)
        write_json_atomic(output, report)
        if document_output is not None:
            try:
                from generar_informe_evidencia import build_report
            except ImportError as exc:
                raise AuditError(
                    "no se pudo generar el DOCX; instale python-docx "
                    "(python -m pip install python-docx)"
                ) from exc
            build_report(
                report,
                output.expanduser().resolve(),
                document_output,
            )
    except AuditError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    if not args.quiet:
        print_summary(
            report,
            output.resolve(),
            document_output.expanduser().resolve() if document_output else None,
        )
    return 2 if _should_fail(report, args.fail_on) else 0


if __name__ == "__main__":
    raise SystemExit(main())
