import json
import tempfile
import threading
import unittest
import urllib.request
from pathlib import Path

from interfaz_auditor import (
    AuditOptions,
    AuditorHTTPServer,
    AuditorHandler,
    IdentityCredential,
    build_auditor_command,
    build_process_environment,
    build_selector_command,
    options_from_payload,
    read_evidence_summary,
    validate_options,
)


class InterfazAuditorTest(unittest.TestCase):
    def _options(self, root: Path, **overrides):
        repository = root / "repo"
        repository.mkdir()
        config = root / "policy.json"
        config.write_text("{}", encoding="utf-8")
        values = {
            "repository": repository,
            "config": config,
            "output_dir": root / "resultados",
            "pillars": (1, 2, 3),
            "condition": "B",
            "authorized": True,
            "active_tests": True,
            "generate_docx": True,
        }
        values.update(overrides)
        return AuditOptions(**values)

    def test_comando_incluye_tres_pilares_y_salidas_profesionales(self):
        with tempfile.TemporaryDirectory() as temporary:
            options = self._options(Path(temporary))
            command = build_auditor_command(options, python_executable="python", script_path="auditor.py")
        self.assertIn("1,2,3", command)
        self.assertIn("--autorizado", command)
        self.assertIn("--permitir-pruebas-activas", command)
        self.assertIn("--out-docx", command)
        self.assertTrue(any("Informe_Profesional_Ciberseguridad_B.docx" in item for item in command))

    def test_validacion_exige_autorizacion(self):
        with tempfile.TemporaryDirectory() as temporary:
            options = self._options(Path(temporary), authorized=False)
            errors = validate_options(options)
        self.assertTrue(any("autorizados" in error for error in errors))

    def test_credenciales_solo_se_agregan_al_entorno(self):
        with tempfile.TemporaryDirectory() as temporary:
            options = self._options(
                Path(temporary),
                identities=(
                    IdentityCredential("A", "ana", "secreto-a"),
                    IdentityCredential("B", "bruno", "secreto-b"),
                    IdentityCredential("C", "carla", "secreto-c"),
                ),
            )
            command = build_auditor_command(options)
            environment = build_process_environment(options, {"BASE": "1"})
        self.assertNotIn("secreto-a", command)
        self.assertNotIn("secreto-b", command)
        self.assertEqual(environment["AUDITOR_TRAMITIA_PASSWORD_A"], "secreto-a")
        self.assertEqual(environment["AUDITOR_TRAMITIA_PASSWORD_B"], "secreto-b")
        self.assertEqual(environment["AUDITOR_TRAMITIA_USER_C"], "carla")
        self.assertEqual(environment["AUDITOR_TRAMITIA_PASSWORD_C"], "secreto-c")
        self.assertNotIn("secreto-c", command)

    def test_selector_usa_componente_python_independiente(self):
        command = build_selector_command("repository", "C:\\laboratorio")

        self.assertTrue(any(item.endswith("selector_archivos.py") for item in command))
        self.assertIn("repository", command)
        self.assertNotIn("powershell.exe", command)

    def test_payload_admite_identidades_a_b_y_c(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "repo"
            repository.mkdir()
            config = root / "policy.json"
            config.write_text("{}", encoding="utf-8")
            options = options_from_payload({
                "repository": str(repository),
                "config": str(config),
                "output_dir": str(root / "resultados"),
                "pillars": [1, 2, 3],
                "authorized": True,
                "identities": [
                    {"label": "A", "username": "ana", "password": "a"},
                    {"label": "B", "username": "bruno", "password": "b"},
                    {"label": "C", "username": "carla", "password": "c"},
                ],
            })
        self.assertEqual(["A", "B", "C"], [item.label for item in options.identities])

    def test_lee_resumen_de_evidencia(self):
        fixture = {
            "corrida": {"condicion": "B"},
            "resumen": {
                "por_estado": {"CONFIRMADO": 2, "REQUIERE_REVISION": 1},
                "por_severidad": {"CRITICA": 1, "ALTA": 1, "MEDIA": 0},
            },
            "runtime": {"peticiones_realizadas": 7},
            "alcance": {"archivos_inventariados": 12},
            "hallazgos": [{"regla_id": "P1"}, {"regla_id": "P2"}, {"regla_id": "P3"}],
            "comparacion_ab": {
                "instrumento_identico": True,
                "politica_identica": True,
                "reglas_con_cambio": ["P1"],
            },
        }
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "evidencia.json"
            path.write_text(json.dumps(fixture), encoding="utf-8")
            summary = read_evidence_summary(path)
        self.assertEqual(summary["condition"], "B")
        self.assertEqual(summary["findings"], 3)
        self.assertTrue(summary["comparable"])
        self.assertEqual(summary["changed_rules"], ["P1"])

    def test_servidor_solo_local_entrega_interfaz_y_protege_api(self):
        server = AuditorHTTPServer(("127.0.0.1", 0), AuditorHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_address[1]}"
        try:
            html = urllib.request.urlopen(base + "/", timeout=3).read().decode("utf-8")
            self.assertIn("Auditor de Ciberseguridad", html)
            self.assertIn('id="add-identity"', html)
            self.assertNotIn("Nombre ficticio", html)
            self.assertNotIn("__AUDITOR_TOKEN__", html)
            request = urllib.request.Request(base + "/api/status", headers={"X-Auditor-Token": server.token})
            status = json.loads(urllib.request.urlopen(request, timeout=3).read())
            self.assertEqual(status["status"], "idle")
            self.assertEqual(server.server_address[0], "127.0.0.1")
            shutdown = urllib.request.Request(
                base + "/api/shutdown",
                data=b"{}",
                method="POST",
                headers={"Content-Type": "application/json", "X-Auditor-Token": server.token},
            )
            response = json.loads(urllib.request.urlopen(shutdown, timeout=3).read())
            self.assertTrue(response["ok"])
            thread.join(timeout=3)
            self.assertFalse(thread.is_alive())
        finally:
            if thread.is_alive():
                server.shutdown()
            server.server_close()
            thread.join(timeout=3)


if __name__ == "__main__":
    unittest.main()
