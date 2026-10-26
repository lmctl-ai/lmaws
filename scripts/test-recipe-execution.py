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
        self.env["PATH"] = str(ROOT / "target") + os.pathsep + str(ROOT / "build") + os.pathsep + self.env.get("PATH", "")
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
                f'import "{base}/lifecycle.lms"; import "{base}/prefix.lms"; import "{base}/audits.lms"; import "{base}/spend.lms";\n',
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
            'import "' + str(ROOT / "recipes" / "lib" / "inventory.lms") + '";\n'
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

    def test_inherited_live_flag_stays_synthetic_for_picture_example(self) -> None:
        env = dict(self.env, LMAWS_LIVE="1", AWS_PROFILE="default")
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
        self.assertFalse(list(self.work.rglob("*.jsonl")), "synthetic picture must not create a private ledger")
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
        code='import '+json.dumps(str(ROOT/'recipes/lib/common.lms'))+';\n'
        for symbol,path in [('one',first),('two',second)]:
            code+=symbol+' = _dsl_ cli="lmaws --dry-run" install="github:lmctl-ai/lmaws@latest";\n'
            code+='let cloud=aws.example("recipe_budget_fixture");\nfile_write('+json.dumps(str(path))+',"executed");\nend _dsl_\n'
        code+='recipe_run(one,{live:true,cap:0.20,profile:"default",output:'+json.dumps(str(self.work/'one'))+'});\n'
        code+='recipe_run(two,{live:true,cap:0.06,profile:"default",output:'+json.dumps(str(self.work/'two'))+'});\n'
        entry.write_text(code)
        result=self.run_script(entry)
        self.assertNotEqual(result.returncode,0)
        self.assertIn("whole-run cap exceeded",result.stdout,result.stdout+result.stderr)
        self.assertTrue(first.exists())
        self.assertFalse(second.exists())



if __name__ == "__main__":
    unittest.main(verbosity=2)
