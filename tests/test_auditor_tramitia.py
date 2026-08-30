"""Pruebas del auditor comparativo de los tres pilares."""

from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path
from zipfile import ZipFile


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from auditor_tramitia import (  # noqa: E402
    AUDIT_GENESIS_HASH,
    AuditError,
    HttpClient,
    HttpResponse,
    analizar_repositorio,
    audit_event_hash,
    auditar_aplicacion,
    compare_evidence_reports,
    main,
    pilar3_auditoria_sin_firma,
    verify_audit_hash_chain,
)


HASH_CERO = "sha256:" + "0" * 64


class FakeHttpClient:
    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []
        self.request_count = 0
        self.base_url = "http://127.0.0.1:5050"

    def request(self, method, path, **kwargs):
        self.requests.append((method, path, kwargs))
        self.request_count += 1
        if not self.responses:
            raise AssertionError("el control hizo mas peticiones de las previstas")
        return self.responses.pop(0)


def response(status, payload=None, headers=None):
    body = b"" if payload is None else json.dumps(payload).encode("utf-8")
    return HttpResponse(
        status=status,
        headers={str(key).lower(): str(value) for key, value in (headers or {}).items()},
        body=body,
    )


def chained_events(*events):
    result = []
    previous = AUDIT_GENESIS_HASH
    for raw in events:
        event = dict(raw)
        event["hash_anterior"] = previous
        event["hash_evento"] = audit_event_hash(previous, event)
        previous = event["hash_evento"]
        result.append(event)
    return result


class AuditorCadenaSuministroTest(unittest.TestCase):
    def make_repo(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        return Path(temporary.name)

    def rule_findings(self, report, rule_id):
        return [item for item in report["hallazgos"] if item["regla_id"] == rule_id]

    def test_requirements_movil_sin_lock_ni_hash_genera_evidencia(self):
        root = self.make_repo()
        (root / "requirements.txt").write_text("demo>=1.0\n", encoding="utf-8")

        report = analizar_repositorio(root)

        self.assertTrue(self.rule_findings(report, "R-A03-001"))
        self.assertTrue(self.rule_findings(report, "R-A03-002"))
        self.assertTrue(self.rule_findings(report, "R-A08-001"))
        finding = self.rule_findings(report, "R-A03-001")[0]
        self.assertEqual("requirements.txt", finding["archivo"])
        self.assertEqual(1, finding["ubicacion"]["linea_inicio"])
        self.assertEqual("demo", finding["componente"])
        self.assertEqual("CONFIRMADO", finding["estado_final"])

    def test_requirements_fijado_con_hash_funciona_como_lock_reproducible(self):
        root = self.make_repo()
        line = f"demo==1.0.0 --hash={HASH_CERO}\n"
        (root / "requirements.txt").write_text(line, encoding="utf-8")
        (root / "requirements.lock").write_text(line, encoding="utf-8")

        report = analizar_repositorio(root)

        self.assertFalse(self.rule_findings(report, "R-A03-001"))
        self.assertFalse(self.rule_findings(report, "R-A03-002"))
        self.assertFalse(self.rule_findings(report, "R-A03-003"))
        self.assertFalse(self.rule_findings(report, "R-A08-001"))

    def test_package_lock_consistente_no_es_hallazgo(self):
        root = self.make_repo()
        (root / "package.json").write_text(
            json.dumps({"dependencies": {"demo": "1.2.3"}}), encoding="utf-8"
        )
        (root / "package-lock.json").write_text(
            json.dumps(
                {
                    "lockfileVersion": 3,
                    "packages": {
                        "": {"dependencies": {"demo": "1.2.3"}},
                        "node_modules/demo": {"version": "1.2.3"},
                    },
                }
            ),
            encoding="utf-8",
        )

        report = analizar_repositorio(root)

        self.assertFalse(self.rule_findings(report, "R-A03-001"))
        self.assertFalse(self.rule_findings(report, "R-A03-002"))
        self.assertFalse(self.rule_findings(report, "R-A03-003"))

    def test_accion_github_fijada_a_tag_se_reporta_como_movil(self):
        root = self.make_repo()
        workflow = root / ".github" / "workflows"
        workflow.mkdir(parents=True)
        (workflow / "ci.yml").write_text(
            "steps:\n  - uses: actions/checkout@v4\n", encoding="utf-8"
        )

        report = analizar_repositorio(root)

        findings = self.rule_findings(report, "R-A03-008")
        self.assertEqual(1, len(findings))
        self.assertEqual("actions/checkout", findings[0]["componente"])
        self.assertEqual(2, findings[0]["ubicacion"]["linea_inicio"])

    def test_fuente_fuera_de_allowlist_se_reporta_sin_exponer_credencial(self):
        root = self.make_repo()
        (root / "requirements.txt").write_text(
            f"demo @ https://token:secreto@fuente.example/demo.whl --hash={HASH_CERO}\n",
            encoding="utf-8",
        )

        report = analizar_repositorio(root)

        findings = self.rule_findings(report, "R-A03-007")
        self.assertEqual(1, len(findings))
        serialized = json.dumps(report, ensure_ascii=False)
        self.assertNotIn("secreto", serialized)
        self.assertIn("fuente.example", serialized)

    def test_hash_de_artefacto_coincidente_y_modificado(self):
        root = self.make_repo()
        artifacts = root / "artifacts"
        artifacts.mkdir()
        artifact = artifacts / "componente.bin"
        artifact.write_bytes(b"contenido-controlado")
        expected = "sha256:" + hashlib.sha256(b"contenido-controlado").hexdigest()
        config = {
            "integrity_required_globs": ["artifacts/**"],
            "expected_hashes": {"artifacts/componente.bin": expected},
        }

        first = analizar_repositorio(root, configuracion=config)
        self.assertFalse(self.rule_findings(first, "R-A08-001"))
        self.assertFalse(self.rule_findings(first, "R-A08-002"))

        artifact.write_bytes(b"contenido-alterado")
        second = analizar_repositorio(root, configuracion=config)
        mismatch = self.rule_findings(second, "R-A08-002")
        self.assertEqual(1, len(mismatch))
        self.assertEqual("CRITICA", mismatch[0]["severidad"])

    def test_descarga_en_ci_sin_verificacion_cercana_se_reporta(self):
        root = self.make_repo()
        workflow = root / ".github" / "workflows"
        workflow.mkdir(parents=True)
        (workflow / "build.yml").write_text(
            "steps:\n  - run: curl -o tool.bin https://example.test/tool.bin\n  - run: ./tool.bin\n",
            encoding="utf-8",
        )

        report = analizar_repositorio(root)

        findings = self.rule_findings(report, "R-A08-003")
        self.assertEqual(1, len(findings))
        self.assertEqual("MEDIA", findings[0]["confianza"])

    def test_healthcheck_local_con_curl_no_se_confunde_con_descarga(self):
        root = self.make_repo()
        workflow = root / ".github" / "workflows"
        workflow.mkdir(parents=True)
        (workflow / "health.yml").write_text(
            "steps:\n  - run: curl -sf http://127.0.0.1:5050/health > /dev/null\n",
            encoding="utf-8",
        )

        report = analizar_repositorio(root)

        self.assertFalse(self.rule_findings(report, "R-A08-003"))

    def test_condiciones_a_y_b_ejecutan_las_mismas_reglas(self):
        root = self.make_repo()
        (root / "requirements.txt").write_text("demo>=1\n", encoding="utf-8")

        baseline = analizar_repositorio(root, modo_control=False)
        intervention = analizar_repositorio(root, modo_control=True)

        self.assertEqual("A", baseline["corrida"]["condicion"])
        self.assertEqual("B", intervention["corrida"]["condicion"])
        self.assertTrue(baseline["hallazgos"])
        self.assertTrue(baseline["componentes"])
        self.assertEqual(
            [(item["regla_id"], item["resultado"]) for item in baseline["resultados_reglas"]],
            [(item["regla_id"], item["resultado"]) for item in intervention["resultados_reglas"]],
        )
        self.assertTrue(baseline["diseno_comparativo"]["instrumento_identico_en_a_y_b"])

        comparison = compare_evidence_reports(baseline, intervention)
        self.assertTrue(comparison["instrumento_identico"])
        self.assertTrue(comparison["politica_identica"])
        self.assertEqual([], comparison["reglas_con_cambio"])

    def test_cadena_de_auditoria_valida_y_detecta_copia_alterada(self):
        events = chained_events(
            {"ts": "2026-08-30T00:00:00+00:00", "event": "inicio"},
            {"ts": "2026-08-30T00:00:01+00:00", "event": "herramienta.ejecutada"},
        )

        verification = verify_audit_hash_chain(events)
        evaluation = pilar3_auditoria_sin_firma(events)

        self.assertTrue(verification["valida"])
        self.assertEqual(2, verification["eventos_verificados"])
        self.assertFalse(evaluation["vulnerable"])
        self.assertTrue(evaluation["alteracion_controlada_detectada"])
        self.assertEqual(
            0,
            evaluation["verificacion_copia_alterada"]["primer_indice_invalido"],
        )

    def test_cadena_de_auditoria_sin_hash_se_reporta_invalida(self):
        verification = verify_audit_hash_chain(
            [{"ts": "2026-08-30T00:00:00+00:00", "event": "inicio"}]
        )

        self.assertFalse(verification["valida"])
        self.assertEqual(0, verification["primer_indice_invalido"])
        self.assertIn("faltan", verification["razon"])

    def test_cli_exige_confirmacion_de_autorizacion(self):
        root = self.make_repo()
        with redirect_stderr(StringIO()):
            with self.assertRaises(SystemExit) as raised:
                main(["--repo", str(root)])
        self.assertEqual(2, raised.exception.code)

    def test_cli_genera_informe_docx_opcional(self):
        root = self.make_repo()
        evidence = root / "evidencia.json"
        document = root / "informe.docx"

        result = main(
            [
                "--repo",
                str(root),
                "--pilares",
                "3",
                "--out",
                str(evidence),
                "--out-docx",
                str(document),
                "--autorizado",
                "--quiet",
            ]
        )

        self.assertEqual(0, result)
        self.assertTrue(evidence.is_file())
        self.assertTrue(document.is_file())
        with ZipFile(document) as archive:
            self.assertIn("word/document.xml", archive.namelist())

    def test_salida_declara_que_no_uso_red_ni_ejecuto_el_repositorio(self):
        root = self.make_repo()

        report = analizar_repositorio(root)

        self.assertFalse(report["tool"]["network_used"])
        self.assertFalse(report["tool"]["repository_executed"])
        self.assertFalse(report["tool"]["repository_modified"])

    def test_corrida_unificada_promueve_hallazgos_de_los_tres_pilares(self):
        root = self.make_repo()
        (root / "requirements.txt").write_text("demo>=1\n", encoding="utf-8")
        (root / "settings.py").write_text("DEBUG = True\n", encoding="utf-8")
        config = {
            "runtime": {
                "identities": {},
                "checks": [
                    {
                        "id": "P1-TEST",
                        "pillar": 1,
                        "type": "auth_required",
                        "title": "Anonimo permitido",
                        "request": {"method": "GET", "path": "/privado"},
                    },
                    {
                        "id": "P2-CORS-TEST",
                        "pillar": 2,
                        "type": "cors_policy",
                        "title": "CORS inseguro",
                        "request": {"method": "GET", "path": "/api"},
                        "origin": "https://mal.example",
                    },
                    {
                        "id": "P2-SOURCE-TEST",
                        "pillar": 2,
                        "type": "source_regex_absent",
                        "title": "Debug activo",
                        "files": ["settings.py"],
                        "patterns": ["DEBUG\\s*=\\s*True"],
                    },
                ],
            }
        }
        client = FakeHttpClient(
            [
                response(200),
                response(
                    200,
                    headers={
                        "Access-Control-Allow-Origin": "https://mal.example",
                        "Access-Control-Allow-Credentials": "true",
                    },
                ),
            ]
        )

        report = auditar_aplicacion(
            root,
            pilares=(1, 2, 3),
            configuracion=config,
            runtime_client=client,
        )

        self.assertEqual([1, 2, 3], report["corrida"]["pilares_ejecutados"])
        self.assertEqual({1, 2, 3}, {item["pilar"] for item in report["hallazgos"]})
        self.assertEqual(2, report["runtime"]["peticiones_realizadas"])
        self.assertTrue(report["tool"]["network_used"])
        self.assertIn("1", report["resumen_por_pilar"])
        self.assertIn("2", report["resumen_por_pilar"])
        self.assertIn("3", report["resumen_por_pilar"])

    def test_condicion_a_tambien_ejecuta_controles_runtime(self):
        root = self.make_repo()
        config = {
            "runtime": {
                "identities": {},
                "checks": [
                    {
                        "id": "P1-AUTH-BASELINE",
                        "pillar": 1,
                        "type": "auth_required",
                        "title": "Anonimo permitido",
                        "request": {"method": "GET", "path": "/privado"},
                    }
                ],
            }
        }
        client = FakeHttpClient([response(200)])

        report = auditar_aplicacion(
            root,
            pilares=(1,),
            modo_control=False,
            configuracion=config,
            runtime_client=client,
        )

        self.assertEqual("A", report["corrida"]["condicion"])
        finding = next(
            item for item in report["hallazgos"] if item["regla_id"] == "P1-AUTH-BASELINE"
        )
        self.assertEqual("CONFIRMADO", finding["estado_final"])
        self.assertEqual("A", finding["condicion"])

    def test_acceso_cruzado_confirma_bola_solo_si_precondicion_es_valida(self):
        root = self.make_repo()
        config = {
            "runtime": {
                "identities": {
                    "owner": {"username": "ana", "password": "a"},
                    "other": {"username": "bruno", "password": "b"},
                },
                "checks": [
                    {
                        "id": "P1-BOLA-TEST",
                        "pillar": 1,
                        "type": "cross_object_access",
                        "title": "BOLA",
                        "owner_identity": "owner",
                        "other_identity": "other",
                        "request": {"method": "GET", "path": "/objetos/1"},
                    }
                ],
            }
        }
        client = FakeHttpClient([response(200), response(200)])

        report = auditar_aplicacion(
            root,
            pilares=(1,),
            configuracion=config,
            runtime_client=client,
        )

        finding = next(item for item in report["hallazgos"] if item["regla_id"] == "P1-BOLA-TEST")
        self.assertEqual("CONFIRMADO", finding["estado_final"])
        self.assertEqual(["ana", "bruno"], [item[2]["username"] for item in client.requests])
        serialized = json.dumps(report)
        self.assertNotIn('"password": "a"', serialized)
        self.assertNotIn('"password": "b"', serialized)

    def test_identidad_efectiva_prohibida_se_confirma_por_json_path(self):
        root = self.make_repo()
        config = {
            "runtime": {
                "identities": {"low": {"username": "u", "password": "p"}},
                "checks": [
                    {
                        "id": "P1-AGENT-TEST",
                        "pillar": 1,
                        "type": "json_value_policy",
                        "title": "Escalada",
                        "identity": "low",
                        "request": {"method": "POST", "path": "/agent", "json": {"tarea": "x"}},
                        "json_path": "$.identidad_efectiva.role",
                        "disallowed_values": ["coordinador"],
                    }
                ],
            }
        }
        client = FakeHttpClient(
            [response(200, {"identidad_efectiva": {"role": "coordinador"}})]
        )

        report = auditar_aplicacion(
            root,
            pilares=(1,),
            configuracion=config,
            runtime_client=client,
        )

        self.assertTrue(
            any(item["regla_id"] == "P1-AGENT-TEST" for item in report["hallazgos"])
        )

    def test_control_runtime_del_pilar3_verifica_integridad_y_alteracion(self):
        root = self.make_repo()
        events = chained_events(
            {"ts": "2026-08-30T00:00:00+00:00", "event": "inicio"},
            {"ts": "2026-08-30T00:00:01+00:00", "event": "acceso.concedido"},
        )
        config = {
            "runtime": {
                "identities": {"auditor": {"username": "u", "password": "p"}},
                "checks": [
                    {
                        "id": "P3-AUDIT-TEST",
                        "pillar": 3,
                        "type": "audit_hash_chain",
                        "title": "Cadena de auditoria",
                        "identity": "auditor",
                        "request": {"method": "GET", "path": "/api/admin/auditoria"},
                        "events_json_path": "$.eventos",
                    }
                ],
            }
        }
        client = FakeHttpClient([response(200, {"eventos": events})])

        report = auditar_aplicacion(
            root,
            pilares=(3,),
            configuracion=config,
            runtime_client=client,
        )

        event = next(
            item
            for item in report["resultados_reglas"]
            if item["regla_id"] == "P3-AUDIT-TEST"
        )
        self.assertEqual("PASS", event["resultado"])
        self.assertFalse(
            any(item["regla_id"] == "P3-AUDIT-TEST" for item in report["hallazgos"])
        )
        self.assertEqual(1, client.request_count)

    def test_prueba_activa_se_omite_sin_autorizacion_adicional(self):
        root = self.make_repo()
        config = {
            "runtime": {
                "identities": {"user": {"username": "u", "password": "p"}},
                "checks": [
                    {
                        "id": "P1-BRUTE-TEST",
                        "pillar": 1,
                        "type": "brute_force_protection",
                        "title": "Fuerza bruta",
                        "active": True,
                        "attempts": 3,
                        "identity": "user",
                        "request": {"method": "POST", "path": "/login", "json": {}},
                    }
                ],
            }
        }
        client = FakeHttpClient([])

        report = auditar_aplicacion(
            root,
            pilares=(1,),
            configuracion=config,
            runtime_client=client,
        )

        event = next(item for item in report["resultados_reglas"] if item["regla_id"] == "P1-BRUTE-TEST")
        self.assertEqual("SKIP_JUSTIFICADO", event["resultado"])
        self.assertEqual(0, client.request_count)

    def test_cliente_http_rechaza_destino_no_loopback_por_defecto(self):
        with self.assertRaises(AuditError):
            HttpClient("https://example.com")


if __name__ == "__main__":
    unittest.main()
