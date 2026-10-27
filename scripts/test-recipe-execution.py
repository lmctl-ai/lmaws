#!/usr/bin/env python3
"""Offline execution and import-safety checks for the lmaws recipe wrappers."""
from __future__ import annotations

import http.server
import json
import os
import shutil
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LMSCRIPT = shutil.which("lmscript")


class RecipeExecutionTests(unittest.TestCase):
    def setUp(self) -> None:
        if not LMSCRIPT:
            self.skipTest("lmscript is not installed")
        self.env = dict(os.environ)
        selected = self.env.get("LMAWS_TEST_HOST")
        if selected:
            self.env["PATH"] = str(Path(selected).resolve().parent) + os.pathsep + self.env.get("PATH", "")
        elif not shutil.which("lmaws", path=self.env.get("PATH", "")):
            self.env["PATH"] = str(ROOT / "target/jvm-bin") + os.pathsep + str(ROOT / "target") + os.pathsep + self.env.get("PATH", "")
        self.env.update(CI="true", LMAWS_LIVE="0", AWS_EC2_METADATA_DISABLED="true")
        for key in ("AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_REGION", "AWS_DEFAULT_REGION"):
            self.env.pop(key, None)
        self.env.pop("LMAWS_ENDPOINT", None)
        for key in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN", "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_ROLE_ARN", "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "AWS_CONTAINER_CREDENTIALS_FULL_URI"):
            self.env.pop(key, None)
        self.work = Path(tempfile.mkdtemp(prefix="lmaws-recipes-test-"))

    def tearDown(self) -> None:
        shutil.rmtree(self.work, ignore_errors=True)

    def run_script(self, source: Path, *args: str, timeout: int = 120) -> subprocess.CompletedProcess[str]:
        return subprocess.run([LMSCRIPT, str(source), *args], cwd=self.work, env=self.env, text=True, capture_output=True, timeout=timeout)

    def test_local_http_imports_have_no_execution_effects(self) -> None:
        served = ROOT / "recipes" / "lib"
        hits: list[str] = []

        class Handler(http.server.SimpleHTTPRequestHandler):
            def log_message(self, *_: object) -> None:
                pass

            def do_GET(self) -> None:  # noqa: N802
                hits.append(self.path)
                return super().do_GET()

        old = os.getcwd()
        os.chdir(served)
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            base = f"http://127.0.0.1:{server.server_port}"
            entry = self.work / "imports.lms"
            entry.write_text(
                f'import "{base}/common.lms"; import "{base}/inventory.lms"; '
                f'import "{base}/lifecycle.lms"; import "{base}/prefix.lms"; import "{base}/audits.lms"; import "{base}/spend.lms"; import "{base}/iam_policy.lms"; import "{base}/policy_builder.lms";\n',
                encoding="utf-8",
            )
            result = self.run_script(entry)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertGreaterEqual(len(hits), 3, hits)
            self.assertEqual(list(self.work.iterdir()), [entry])
        finally:
            server.shutdown()
            server.server_close()
            os.chdir(old)

    def test_inventory_queue_top_two_is_synthetic_and_bounded(self) -> None:
        output = self.work / "inventory"
        result = self.run_script(ROOT / "recipes" / "inventory.lms", "--task", "queues", "--top", "2", "--output", str(output))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        rows = json.loads((output.with_suffix(".json")).read_text(encoding="utf-8"))
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(row["kind"] == "queue" for row in rows))
        self.assertFalse(list(output.parent.glob("inventory.roles.raw.json")))
        self.assertIn("estimated cost: $", result.stdout)
        self.assertNotIn("--dsl", result.stdout)

    def test_two_partial_inventory_calls_restore_environment(self) -> None:
        entry = self.work / "compose.lms"
        entry.write_text(
            'import ' + json.dumps((ROOT / "recipes" / "lib" / "inventory.lms").as_posix()) + ';\n'
            'a=recipe_inventory({task:"queues",top:2,output:"data/queues"});\n'
            'b=recipe_inventory({task:"tables",top:2,output:"data/tables"});\n'
            'assert(a.rows.len()==2); assert(b.rows.len()==2);\n',
            encoding="utf-8",
        )
        result = self.run_script(entry)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.count("estimated cost: $"), 2)
        self.assertEqual(len(json.loads((self.work / "data/queues.json").read_text())), 2)
        self.assertEqual(len(json.loads((self.work / "data/tables.json").read_text())), 2)

    def test_literal_tilde_output_path_is_accepted_without_shell_expansion(self) -> None:
        entry = self.work / "tilde.lms"
        entry.write_text(
            'import ' + json.dumps((ROOT / "recipes" / "lib" / "inventory.lms").as_posix()) + ';\n'
            'r=recipe_inventory({task:"queues",top:1,output:"~/recipe-output"});\n'
            'assert(r.rows.len()==1);\n', encoding="utf-8")
        result = self.run_script(entry)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue((self.work / "~" / "recipe-output.json").exists())

    def test_admin_profile_is_reserved_for_grant_entrypoints(self) -> None:
        self.env["AWS_PROFILE"] = "admin"
        denied = self.run_script(ROOT / "recipes" / "inventory_queues.lms", "--preview", "--profile", "admin")
        self.assertNotEqual(denied.returncode, 0, "ordinary inventory accepted the admin profile")
        allowed = self.run_script(ROOT / "recipes" / "grant_lambda_role.lms", "--preview", "--apply", "--profile", "admin")
        self.assertEqual(allowed.returncode, 0, allowed.stdout + allowed.stderr)
        report = json.loads((self.work / "data/grant_lambda_role.json").read_text())
        self.assertTrue(report["synthetic"])
        self.assertFalse(report["applied"], "preview plus apply mutated the role")
        self.assertTrue(allowed.stdout.strip().splitlines()[-1].startswith("estimated cost: $"))

    def test_inherited_live_flag_stays_synthetic_for_picture_example(self) -> None:
        empty_config = self.work / "empty-aws-config"
        empty_config.write_text("", encoding="utf-8")
        env = dict(self.env, OS="Windows_NT", LMAWS_LIVE="1", LMAWS_SPEND_LIVE="1",
                   AWS_PROFILE="default", AWS_CONFIG_FILE=str(empty_config),
                   AWS_SHARED_CREDENTIALS_FILE=str(empty_config))
        result = subprocess.run(
            [LMSCRIPT, str(ROOT / "examples" / "recipe_prefix_search.lms")],
            cwd=self.work,
            env=env,
            text=True,
            capture_output=True,
            timeout=180,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue((self.work / "images" / "recipe_prefix_search.png").exists())
        self.assertTrue((self.work / "data" / "recipe_prefix_search.csv").exists())
        self.assertFalse(list((self.work/".lmaws-local").rglob("*.jsonl")), "synthetic discovery must not create private live ledgers")
        ledgers = list(self.work.rglob("*.jsonl"))
        self.assertTrue(ledgers, "synthetic example retains its cost-accounting receipt")
        for ledger in ledgers:
            headers = [json.loads(line) for line in ledger.read_text().splitlines()
                       if json.loads(line).get("event") == "cost_header"]
            self.assertTrue(headers, "receipt must identify its execution mode")
            self.assertTrue(all(row["live"] is False for row in headers),
                            "an inherited live flag must never enable real picture requests")
        self.assertNotIn("AccessDenied", result.stdout + result.stderr)

    def test_preview_has_no_outputs_and_live_requires_apply(self) -> None:
        preview = self.work / "preview"
        result = self.run_script(ROOT / "recipes" / "lifecycle.lms", "--task", "queue", "--preview", "--output", str(preview))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(preview.with_suffix(".json").exists())
        self.assertIn("estimated cost: $0.00", result.stdout)

        # The guard runs before recipe_run, so this cannot invoke a host or create a ledger.
        live = self.run_script(ROOT / "recipes" / "lifecycle.lms", "--task", "queue", "--live", "--profile", "lmaws", "--output", str(self.work / "live"))
        self.assertNotEqual(live.returncode, 0)
        self.assertNotIn("--dsl", live.stdout + live.stderr)
        self.assertFalse((self.work / "live.json").exists())

    def test_shared_live_budget_refuses_second_program_without_cloud_calls(self) -> None:
        # Native --dry-run forces the Cloud fixture backend even while the outer
        # recipe budget is in live mode. CI is also true: no AWS calls are possible.
        first=self.work/"first-marker"
        second=self.work/"second-marker"
        entry=self.work/"budget.lms"
        code='import '+json.dumps((ROOT/'recipes/lib/common.lms').as_posix())+';\n'
        for symbol,path in [('one',first),('two',second)]:
            code+=symbol+' = _dsl_ cli="lmaws --dry-run" install="github:lmctl-ai/lmaws@latest";\n'
            code+='let cloud=aws.example("recipe_budget_fixture");\nfile_write('+json.dumps(str(path))+',"executed");\nend _dsl_\n'
        code+='recipe_run(one,{live:true,cap:0.20,profile:"default",output:'+json.dumps((self.work/'one').as_posix())+'});\n'
        code+='recipe_run(two,{live:true,cap:0.06,profile:"default",output:'+json.dumps((self.work/'two').as_posix())+'});\n'
        entry.write_text(code)
        result=self.run_script(entry)
        self.assertNotEqual(result.returncode,0)
        self.assertIn("whole-run cap exceeded",result.stdout,result.stdout+result.stderr)
        self.assertTrue(first.exists())
        self.assertFalse(second.exists())

    def test_policy_lint_and_grant_session_policy_synthetic_and_guards(self) -> None:
        lint_out = self.work / "policy_lint"
        lint_res = self.run_script(ROOT / "recipes" / "policy_lint.lms", "--output", str(lint_out))
        self.assertEqual(lint_res.returncode, 0, lint_res.stdout + lint_res.stderr)
        lint_report = json.loads(lint_out.with_suffix(".json").read_text(encoding="utf-8"))
        self.assertTrue(lint_report["valid"])
        self.assertEqual(lint_report["statement_count"], 8)
        self.assertIn("estimated cost: $0.00", lint_res.stdout)

        grant_out = self.work / "grant_policy"
        grant_res = self.run_script(ROOT / "recipes" / "grant_session_policy.lms", "--output", str(grant_out))
        self.assertEqual(grant_res.returncode, 0, grant_res.stdout + grant_res.stderr)
        grant_report = json.loads(grant_out.with_suffix(".json").read_text(encoding="utf-8"))
        self.assertFalse(grant_report["applied"])
        self.assertEqual(grant_report["action"], "dry_run")
        self.assertEqual(grant_report["added_count"], 5)
        self.assertEqual(grant_report["modified_count"], 1)
        self.assertIn("IAM policy diff (lmaws_session):", grant_res.stdout)

        # Applying with lmaws profile or without LMAWS_ADMIN_GRANT=1 is refused before any host call
        refused_lmaws = self.run_script(
            ROOT / "recipes" / "grant_session_policy.lms",
            "--live", "--apply", "--profile", "lmaws", "--output", str(self.work / "refused_lmaws")
        )
        self.assertNotEqual(refused_lmaws.returncode, 0)
        self.assertFalse((self.work / "refused_lmaws.json").exists())

        refused_no_grant = self.run_script(
            ROOT / "recipes" / "grant_session_policy.lms",
            "--live", "--apply", "--profile", "admin", "--output", str(self.work / "refused_no_grant")
        )
        self.assertNotEqual(refused_no_grant.returncode, 0)
        self.assertFalse((self.work / "refused_no_grant.json").exists())

        doctor_out = self.work / "session_doctor"
        doctor_res = self.run_script(ROOT / "recipes" / "session_doctor.lms", "--top", "20", "--output", str(doctor_out))
        self.assertEqual(doctor_res.returncode, 0, doctor_res.stdout + doctor_res.stderr)
        doctor_report = json.loads(doctor_out.with_suffix(".json").read_text(encoding="utf-8"))
        self.assertEqual(doctor_report["profile_count"], 4)
        self.assertEqual(doctor_report["probe_count"], 8)
        self.assertEqual(doctor_report["allowed_count"], 6)
        self.assertEqual(doctor_report["guardrail_deny_count"], 2)
        self.assertIn("estimated cost: $0.00", doctor_res.stdout)

        grant_preview = self.run_script(ROOT / "recipes" / "grant_session_policy.lms", "--profile", "admin", "--preview")
        self.assertEqual(grant_preview.returncode, 0, grant_preview.stdout + grant_preview.stderr)
        self.assertIn('"profile": "admin"', grant_preview.stdout)

        # The admin profile is reserved for the grant recipe; every inventory,
        # audit, sandbox, and policy helper rejects it before host execution.
        refused_admin = self.run_script(
            ROOT / "recipes" / "inventory_tables.lms",
            "--profile", "admin", "--output", str(self.work / "refused_inventory_admin")
        )
        self.assertNotEqual(refused_admin.returncode, 0)
        self.assertFalse((self.work / "refused_inventory_admin.json").exists())

    def test_permission_builder_recipes_and_simulator_guards(self) -> None:
        sp_out = self.work / "session_policy"
        sp_res = self.run_script(ROOT / "recipes" / "session_policy.lms", "--domain", "example.com", "--output", str(sp_out))
        self.assertEqual(sp_res.returncode, 0, sp_res.stdout + sp_res.stderr)
        sp_report = json.loads(sp_out.with_suffix(".json").read_text(encoding="utf-8"))
        self.assertTrue(sp_report["lint_valid"])
        self.assertEqual(sp_report["statement_count"], 22)
        self.assertTrue(sp_report["fits_managed"])

        # Compare generated policy against itself via --file -> 22 unchanged, byte_identical=True
        sp_diff_out = self.work / "session_policy_diff"
        sp_diff_res = self.run_script(
            ROOT / "recipes" / "session_policy.lms",
            "--domain", "example.com",
            "--file", str(sp_out) + ".policy.json",
            "--output", str(sp_diff_out),
        )
        self.assertEqual(sp_diff_res.returncode, 0, sp_diff_res.stdout + sp_diff_res.stderr)
        sp_diff_report = json.loads(sp_diff_out.with_suffix(".json").read_text(encoding="utf-8"))
        self.assertEqual(sp_diff_report["snapshot_diff"]["unchanged_count"], 22)
        self.assertTrue(sp_diff_report["snapshot_diff"]["byte_identical"])

        fit_out = self.work / "fit_inline"
        fit_res = self.run_script(ROOT / "recipes" / "policy_fit_inline.lms", "--output", str(fit_out))
        self.assertEqual(fit_res.returncode, 0, fit_res.stdout + fit_res.stderr)
        fit_report = json.loads(fit_out.with_suffix(".json").read_text(encoding="utf-8"))
        self.assertTrue(fit_report["fits_inline"])

        sim_out = self.work / "simulate_probes"
        sim_res = self.run_script(ROOT / "recipes" / "policy_simulate_probes.lms", "--output", str(sim_out))
        self.assertEqual(sim_res.returncode, 0, sim_res.stdout + sim_res.stderr)
        sim_report = json.loads(sim_out.with_suffix(".json").read_text(encoding="utf-8"))
        self.assertEqual(len(sim_report["rows"]), 8)
        self.assertTrue(all(r["passed"] == "true" for r in sim_report["rows"]))

        # Live simulation refuses non-admin profile before host invocation
        refused_sim = self.run_script(
            ROOT / "recipes" / "policy_simulate_probes.lms",
            "--live", "--profile", "lmaws", "--output", str(self.work / "refused_sim")
        )
        self.assertNotEqual(refused_sim.returncode, 0)
        self.assertFalse((self.work / "refused_sim.json").exists())



if __name__ == "__main__":
    unittest.main(verbosity=2)
