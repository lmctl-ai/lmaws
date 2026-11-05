#!/usr/bin/env bash
# Live integration test (CI: push -> build -> integration test -> release). Read-only checks of the cert environment with
# the OIDC / assumed-role session in the environment: lmaws builds clients from a NAMED profile only, so the profile
# "default" gets a credential_process that prints the session already in this process's environment. Nothing is stored.
# usage: LMAWS_BIN=/path/to/lmaws scripts/test-live-cert.sh      (needs lmscript on PATH and the lane role's AWS_* variables)
set -euo pipefail
: "${LMAWS_BIN:?path of the lmaws binary under test}" "${AWS_ACCESS_KEY_ID:?}" "${AWS_SECRET_ACCESS_KEY:?}" "${AWS_SESSION_TOKEN:?}"
bucket=${CERT_BUCKET:-lmctl-ai-cert-lmtext-254332045686}
turns=${CERT_TURN_COST_TABLE:-globalweb-cert-turn-cost}
rates=${CERT_RATELIMIT_TABLE:-globalweb-cert-provider-ratelimit}
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
home="$work/home"; mkdir -p "$home/.aws"
cat > "$work/creds.sh" <<'S'
#!/usr/bin/env bash
printf '{"Version":1,"AccessKeyId":"%s","SecretAccessKey":"%s","SessionToken":"%s"}\n' "$AWS_ACCESS_KEY_ID" "$AWS_SECRET_ACCESS_KEY" "$AWS_SESSION_TOKEN"
S
chmod +x "$work/creds.sh"
printf '[default]\ncredential_process = %s\nregion = us-east-1\n' "$work/creds.sh" > "$home/.aws/config"
cat > "$work/live.lms" <<E2
s = load_schema(cli="lmaws");
p = _lmcode_ s;
let cloud = aws.region("us-east-1");
file_write("identity.json", cloud.identity().json());
check(cloud.resource_exists("bucket", "$bucket"));
check(cloud.resource_exists("table", "$turns"));
check(cloud.resource_exists("table", "$rates"));
end _lmcode_
r = run_lmcode(p);
if (!r.ok) { println(r.code, r.message); }
assert(r.ok, "lmaws live checks failed (a missing resource fails check())");
let who = read_file("identity.json");
assert(contains(who, ":assumed-role/lmctl-ai-ci-cert/"), "the caller is not the lane role");
println("lmaws live (read-only): caller is the lane role; $bucket, $turns, $rates exist");
E2
mkdir -p "$work/bin" && ln -s "$(readlink -f "$LMAWS_BIN")" "$work/bin/lmaws"
cd "$work" && PATH="$work/bin:$PATH" HOME="$home" AWS_PROFILE=default LMAWS_LIVE=1 AWS_REGION=us-east-1 AWS_EC2_METADATA_DISABLED=true lmscript live.lms
