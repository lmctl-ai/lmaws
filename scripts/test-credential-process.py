#!/usr/bin/env python3
"""Fake-STS conformance checks for the isolated credential-process helper.

The server is loopback-only and receives no real credentials.  These checks keep
the request contract in sync with the local Python session helper without ever
invoking its AWS CLI path.
"""
import http.server
import importlib.util
import json
import os
import pathlib
import subprocess
import tempfile
import threading
import urllib.parse
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
HOST = pathlib.Path(os.environ.get("LMAWS_TEST_HOST", ROOT / "target/jvm-bin/lmaws")).resolve()


class Sts(http.server.BaseHTTPRequestHandler):
    calls = []
    authorizations = []
    fail = False

    def log_message(self, *_args):
        pass

    def do_POST(self):  # noqa: N802
        size = int(self.headers.get("content-length", "0"))
        form = urllib.parse.parse_qs(self.rfile.read(size).decode("utf-8"), keep_blank_values=True)
        Sts.calls.append(form)
        Sts.authorizations.append(self.headers.get("Authorization", ""))
        action = form.get("Action", [""])[0]
        if Sts.fail:
            raw = ("<ErrorResponse><Error><Code>AccessDenied</Code>"
                   "<Message>TOP_SECRET_UPSTREAM_CANARY</Message></Error></ErrorResponse>").encode()
            self.send_response(403)
            self.send_header("content-type", "text/xml")
            self.send_header("content-length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return
        if action == "GetCallerIdentity":
            body = "<GetCallerIdentityResponse><GetCallerIdentityResult><Account>000000000000</Account></GetCallerIdentityResult></GetCallerIdentityResponse>"
        elif action == "GetFederationToken":
            body = ("<GetFederationTokenResponse><GetFederationTokenResult><Credentials>"
                    "<AccessKeyId>ASIA_FAKE</AccessKeyId><SecretAccessKey>SECRET_FAKE</SecretAccessKey>"
                    "<SessionToken>TOKEN_FAKE</SessionToken><Expiration>2099-01-01T00:00:00Z</Expiration>"
                    "</Credentials></GetFederationTokenResult></GetFederationTokenResponse>")
        else:
            self.send_response(400)
            self.end_headers()
            return
        raw = body.encode()
        self.send_response(200)
        self.send_header("content-type", "text/xml")
        self.send_header("content-length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


def run(extra, *args):
    env = dict(os.environ)
    for key in (
        "LMAWS_ALLOW_ADMIN_SOURCE", "LMAWS_DEFAULT_SESSION_POLICY",
        "LMAWS_CREDENTIAL_SOURCE_PROFILE", "AWS_CONFIG_FILE",
        "AWS_SHARED_CREDENTIALS_FILE", "AWS_ENDPOINT_URL", "AWS_ENDPOINT_URL_STS",
    ):
        env.pop(key, None)
    env.update(extra)
    return subprocess.run([str(HOST), *args], env=env, text=True, capture_output=True, timeout=45)


def check(condition, message):
    if not condition:
        raise AssertionError(message)


def request_fields(form):
    return {k: v[0] for k, v in form.items()}


def python_reference(policy_dir, mode):
    """Return the exact request fields assembled by the checked-in Python helper.

    Its subprocess calls are replaced, so this never runs the AWS CLI or touches
    a real profile.  This is intentionally a contract test, rather than a test
    that merely compares names and actions.
    """
    source = pathlib.Path(os.environ.get(
        "LMAWS_PYTHON_HELPER",
        pathlib.Path.home() / ".aws/session-tools/scripts/aws-profile-session.py"))
    if not source.exists():
        policy = json.loads((pathlib.Path(policy_dir) / "local-default-session.json").read_text())
        compact = json.dumps(policy, separators=(",", ":"), ensure_ascii=True)
        out = {"Name": "awsspot-local-" + mode, "DurationSeconds": "3600",
               "PolicyArns.member.1.arn": ("arn:aws:iam::aws:policy/ReadOnlyAccess"
                  if mode == "default" else "arn:aws:iam::000000000000:policy/lmaws_session")}
        if mode == "default":
            out["Policy"] = compact
        return out
    spec = importlib.util.spec_from_file_location("aws_profile_session_contract", source)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    old = helper.POLICIES
    helper.POLICIES = pathlib.Path(policy_dir)
    try:
        captured = {}
        def fake_run(argv, **kwargs):
            if "get-caller-identity" in argv:
                return subprocess.CompletedProcess(argv, 0, "000000000000\n", "")
            payload = json.loads(argv[argv.index("--cli-input-json") + 1])
            captured.update(payload)
            response = {"Credentials": {"AccessKeyId": "ASIA_REFERENCE", "SecretAccessKey": "REFERENCE_SECRET",
                                         "SessionToken": "REFERENCE_TOKEN", "Expiration": "2099-01-01T00:00:00Z"}}
            return subprocess.CompletedProcess(argv, 0, json.dumps(response), "")
        # credentials_for calls request_for and then its isolated subprocess;
        # patching that subprocess proves the exact generated JSON, without a
        # shell, AWS CLI, or network request.
        with mock.patch.object(helper.subprocess, "run", side_effect=fake_run):
            helper.credentials_for(mode)
        expected = captured
        out = {
            "Name": expected["Name"],
            "DurationSeconds": str(expected["DurationSeconds"]),
        }
        if "Policy" in expected:
            out["Policy"] = expected["Policy"]
        if expected.get("PolicyArns"):
            out["PolicyArns.member.1.arn"] = expected["PolicyArns"][0]["arn"]
        return out
    finally:
        helper.POLICIES = old


def main():
    check(HOST.exists(), f"missing host: {HOST}")
    with tempfile.TemporaryDirectory(prefix="lmaws-credential-process-") as temp:
        root = pathlib.Path(temp)
        aws = root / "aws"
        cache = root / "cache"
        policy = root / "policy.json"
        (aws / "session-tools" / "tasks" / "iam-snapshots").mkdir(parents=True)
        cache.mkdir()
        credentials = aws / "credentials"
        credentials.write_text("[agent-issuer]\naws_access_key_id = AKIA_FAKE\naws_secret_access_key = SOURCE_SECRET\n")
        policy.write_text(json.dumps({"Version": "2012-10-17", "Statement": []}, separators=(",", ":")))
        default_policy = aws / "session-tools" / "tasks" / "iam-snapshots" / "local-default-session.json"
        default_policy.write_text(policy.read_text())

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Sts)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = {
            "LMAWS_TEST_AWS_DIR": str(aws),
            "LMAWS_CREDENTIAL_CACHE_DIR": str(cache),
            "LMAWS_ENDPOINT": f"http://127.0.0.1:{server.server_port}",
            "LMAWS_CREDENTIAL_SOURCE_PROFILE": "agent-issuer",
            "AWS_PROFILE": "default",
            "AWS_EC2_METADATA_DISABLED": "true",
            "LMAWS_CREDENTIAL_PROCESS_CACHE": "0",
            # Ensure an inherited ambient credential cannot accidentally satisfy
            # an implementation that ignores the selected profile.
            "AWS_ACCESS_KEY_ID": "AMBIENT_CANARY",
            "AWS_SECRET_ACCESS_KEY": "AMBIENT_SECRET_CANARY",
        }
        try:
            # Every mode has the Python helper's name and 3600-second duration;
            # managed modes first resolve the source profile account.
            for mode in ("default", "lmaws", "lmaws-ec2", "lmaws-web"):
                Sts.calls.clear()
                result = run(dict(base, LMAWS_DEFAULT_SESSION_POLICY=str(policy)), "--credential-process", mode)
                check(result.returncode == 0, (mode, result.stdout, result.stderr))
                # credential_process stdout necessarily contains the issued
                # secret; ensure the *source* static secret and ambient canary
                # never appear in the output or diagnostics.
                check("SOURCE_SECRET" not in result.stdout + result.stderr
                      and "AMBIENT_CANARY" not in result.stdout + result.stderr,
                      "source or ambient credential leaked")
                out = json.loads(result.stdout)
                check(set(out) == {"Version", "AccessKeyId", "SecretAccessKey", "SessionToken", "Expiration"}
                      and out["Version"] == 1 and out["AccessKeyId"] == "ASIA_FAKE"
                      and out["Expiration"] == "2099-01-01T00:00:00Z", "bad credential_process shape")
                check("Credential=AKIA_FAKE/" in Sts.authorizations[-1]
                      and "AMBIENT_CANARY" not in Sts.authorizations[-1], "wrong source signed STS request")
                calls = [request_fields(c) for c in Sts.calls]
                fed = next(c for c in calls if c.get("Action") == "GetFederationToken")
                check(fed["Name"] == "awsspot-local-" + mode and fed["DurationSeconds"] == "3600", "wrong federation fields")
                if mode == "default":
                    check(fed["PolicyArns.member.1.arn"] == "arn:aws:iam::aws:policy/ReadOnlyAccess", "wrong ReadOnlyAccess ARN")
                    check(fed["Policy"] == policy.read_text(), "policy file was not sent compactly")
                else:
                    check(fed["PolicyArns.member.1.arn"] == "arn:aws:iam::000000000000:policy/lmaws_session", "wrong managed ARN")
                    check("Policy" not in fed, "managed modes must not send inline policy")
                expected = python_reference(aws / "session-tools" / "tasks" / "iam-snapshots", mode)
                if expected is not None:
                    actual_contract = {k: v for k, v in fed.items() if k not in ("Action", "Version")}
                    check(actual_contract == expected,
                          f"request differs from Python helper for {mode}: {fed}")

            # CLI source selection overrides the environment; unset uses agent-issuer.
            selected = run(dict(base, LMAWS_CREDENTIAL_SOURCE_PROFILE="missing-issuer"),
                           "--credential-process", "lmaws", "--source-profile", "agent-issuer")
            check(selected.returncode == 0 and not selected.stderr, "CLI source did not override environment")
            unset = dict(base)
            unset.pop("LMAWS_CREDENTIAL_SOURCE_PROFILE")
            check(run(unset, "--credential-process", "lmaws").returncode == 0, "default source is not agent-issuer")
            before = len(Sts.calls)
            check(run(base, "--credential-process", "lmaws", "--duration", "900").returncode == 1
                  and len(Sts.calls) == before, "non-reference duration was accepted")

            # Refuse admin-like names by default, including names supplied on CLI.
            bad = run(base, "--credential-process", "default", "--source-profile", "admin")
            check(bad.returncode == 1 and not bad.stdout and "agents never use admin" in bad.stderr,
                  "admin source was not refused")
            bad = run(dict(base, LMAWS_CREDENTIAL_SOURCE_PROFILE="corp-admin-issuer"), "--credential-process", "default")
            check(bad.returncode == 1 and not bad.stdout, "admin-containing source was not refused")

            # Unknown modes and malformed/oversize policy files fail without contacting STS.
            before = len(Sts.calls)
            unknown = run(base, "--credential-process", "wat")
            check(unknown.returncode == 1 and len(Sts.calls) == before, "unknown mode reached STS")
            missing = run(dict(base, LMAWS_DEFAULT_SESSION_POLICY=str(root / "missing-policy.json")),
                          "--credential-process", "default")
            check(missing.returncode == 1 and len(Sts.calls) == before, "missing policy reached STS")
            malformed = root / "malformed.json"
            malformed.write_text("not json")
            malformed_result = run(dict(base, LMAWS_DEFAULT_SESSION_POLICY=str(malformed)),
                                   "--credential-process", "default")
            check(malformed_result.returncode == 1 and len(Sts.calls) == before, "malformed policy reached STS")
            huge = root / "huge.json"
            huge.write_text(json.dumps({"Version": "2012-10-17", "Statement": [{"Sid": "x" * 2200}]}))
            oversized = run(dict(base, LMAWS_DEFAULT_SESSION_POLICY=str(huge)), "--credential-process", "default")
            check(oversized.returncode == 1 and len(Sts.calls) == before, "oversize policy was not refused")

            # No ambient credentials/config fallback and no secret in diagnostics.
            no_profile = run(dict(base, LMAWS_TEST_AWS_DIR=str(root / "missing")),
                             "--credential-process", "default")
            check(no_profile.returncode == 1 and "AMBIENT_CANARY" not in no_profile.stderr, "ambient fallback or leak")

            # An explicit --policy-file wins over the environment path.
            explicit = root / "explicit.json"
            explicit.write_text(json.dumps({"Version": "2012-10-17", "Statement": [{"Sid": "Explicit"}]}, separators=(",", ":")))
            Sts.calls.clear()
            chosen = run(dict(base, LMAWS_DEFAULT_SESSION_POLICY=str(root / "missing-policy.json")),
                         "--credential-process", "default", "--policy-file", str(explicit))
            check(chosen.returncode == 0, chosen.stderr)
            chosen_form = next(request_fields(c) for c in Sts.calls if request_fields(c).get("Action") == "GetFederationToken")
            check(chosen_form["Policy"] == explicit.read_text(), "--policy-file did not override env")

            # Cache scope includes the selected source and policy contents.  A
            # policy edit and static-key rotation each force a fresh federation.
            cache_env = dict(base, LMAWS_CREDENTIAL_PROCESS_CACHE="1", LMAWS_DEFAULT_SESSION_POLICY=str(policy))
            Sts.calls.clear()
            first = run(cache_env, "--credential-process", "default")
            second = run(cache_env, "--credential-process", "default")
            check(first.returncode == second.returncode == 0 and len(Sts.calls) == 1,
                  "unchanged cache should avoid a second STS request")
            policy.write_text(json.dumps({"Version": "2012-10-17", "Statement": [{"Sid": "Changed"}]}, separators=(",", ":")))
            changed = run(cache_env, "--credential-process", "default")
            check(changed.returncode == 0 and len(Sts.calls) == 2, "policy change did not invalidate cache")
            credentials.write_text("[agent-issuer]\naws_access_key_id = AKIA_ROTATED\naws_secret_access_key = SECRET_ROTATED\n")
            rotated = run(cache_env, "--credential-process", "default")
            check(rotated.returncode == 0 and len(Sts.calls) == 3, "source credential rotation did not invalidate cache")

            # Selecting a second static profile is a separate cache scope; removing
            # its credentials cannot fall back to the previous profile or disk token.
            credentials.write_text(
                "[agent-issuer]\naws_access_key_id = AKIA_ROTATED\naws_secret_access_key = SECRET_ROTATED\n"
                "[alternate-issuer]\naws_access_key_id = AKIA_ALTERNATE\naws_secret_access_key = SECRET_ALTERNATE\n")
            selected = run(dict(cache_env, LMAWS_CREDENTIAL_SOURCE_PROFILE="alternate-issuer"),
                           "--credential-process", "default")
            check(selected.returncode == 0 and len(Sts.calls) == 4, "source-profile override did not mint a new session")
            credentials.unlink()
            removed = run(dict(cache_env, LMAWS_CREDENTIAL_SOURCE_PROFILE="alternate-issuer"),
                          "--credential-process", "default")
            check(removed.returncode == 1 and len(Sts.calls) == 4, "removed source credentials fell back to cache")

            # Upstream error text is never relayed.  The fake endpoint emits a
            # canary containing a credential-shaped value to make this check hard.
            credentials.write_text("[agent-issuer]\naws_access_key_id = AKIA_FAKE\naws_secret_access_key = SOURCE_SECRET\n")
            Sts.fail = True
            failed = run(dict(base, LMAWS_DEFAULT_SESSION_POLICY=str(policy)), "--credential-process", "default", "--no-cache")
            check(failed.returncode == 1 and not failed.stdout
                  and "TOP_SECRET_UPSTREAM_CANARY" not in failed.stderr
                  and "AWS scoped profile unavailable" in failed.stderr, "STS error leaked")
        finally:
            server.shutdown()
    print("PASS credential-process source isolation, policy sizing, request equivalence and redaction")


if __name__ == "__main__":
    main()
