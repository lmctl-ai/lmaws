# Local build and test gate

Use Java 21+, Maven, Python 3, timeout/coreutils and lmscript >=0.2.420
(the workflow pins lmctl 0.2.420). From the repository root:

```sh
LMAWS_LIVE=0 AWS_EC2_METADATA_DISABLED=true timeout 1800 bash test.sh
# With GraalVM native-image on PATH, after the Maven build:
timeout 2500 bash scripts/build-native.sh
LMAWS_LIVE=0 LMAWS_NATIVE=1 timeout 1800 bash test.sh
```

`test.sh` ensures the pinned SDK, runs `mvn verify`, verifies resolved JAR hashes,
tests independent absence checking and comparison safety, then builds a JVM
wrapper for CLI/schema/notices, SDK regressions, cost/profile/memory enforcement
and actual SDK HTTP transport against loopback fakes. Sixteen inventories and
six tagged lifecycles exercise paging, redaction and failure teardown. Native
mode additionally tests `target/lmaws`, Linux linkage and every gallery example (`scripts/test-gallery.py --run`).
JVM-only mode checks committed gallery assets and explicitly skips rendering.

Native build scripts copy the shaded JAR to an immutable input and use GraalVM
`-O1`, two threads, no fallback and bounded build/runtime heaps. Linux uses dynamic
glibc with static GCC/C++ runtime; linkage and symbol checks enforce glibc >=2.35.
macOS uses system libraries; Windows builds with MSVC and needs the VC++ runtime.
Current Windows release binaries are real native hosts, not stubs.

Local build/tests are the publication gate by user decision; do not wait for CI
or live permissions before publishing. `.github/workflows/ci.yml` remains the
five-platform fake-only release automation. No cloud credentials or GitHub OIDC
are allowed in CI; `LMAWS_LIVE=0` is set there and real-backend CI guards are tested.
GitHub download tokens are not AWS credentials. Live tests are separate opt-in
work, described in [03-live.md](03-live.md).

Generate `schema/lmaws.dsl.json` with the built host (`java -cp target/lmaws-VERSION.jar ai.lmctl.lmaws.Main --lmcode-schema --json > schema/lmaws.dsl.json`). Do not parse/re-serialize or sort its JSON: the CLI gate requires byte-identical output.
