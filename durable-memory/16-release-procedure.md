# Release procedure (one page)

**One release owner at a time.** Several sessions push to `main`; only the session that announced
"I am cutting vX.Y.Z" to the Lead bumps the version and tags. Everyone else keeps pushing to `main`
without touching versions. Tags v0.1.13/14/17 failed partly because several sessions bumped and
tagged concurrently.

**Versioning.** Patch releases only (`0.1.N`): the next N is one more than the highest existing tag
(`git ls-remote --tags origin`), even when a tag failed and has no release. Never reuse a version.
The version lives in `pom.xml`, `Main.VERSION` and its help text, `test.sh`, `scripts/test-cli.py`
and `scripts/build-native.{sh,ps1}`; bump all of them in one commit.

**Cut a release.**

1. `git pull --rebase origin main`; bump the version (one commit); regenerate
   `schema/lmaws.dsl.json` from the host if the API changed.
2. Local gate: `LMAWS_LIVE=0 AWS_EC2_METADATA_DISABLED=true bash test.sh` must pass (and the native
   gate when GraalVM is available). Push to `main`.
3. Tag the pushed commit and dispatch the workflow on the tag (CI never runs on push):
   `git tag -a vX.Y.Z -m "lmaws X.Y.Z" && git push origin vX.Y.Z`
   `gh workflow run ci.yml -R lmctl-ai/lmaws --ref vX.Y.Z`
4. Watch `gh run list -R lmctl-ai/lmaws -L 3`. The release job publishes when the four Linux/macOS
   lanes pass; a failed Windows lane publishes without the Windows binary and says so in the notes.
5. Prove it: `mvn -q package` at the tag, then `python3 scripts/release-proof.py vX.Y.Z`
   (SHA256SUMS, linkage, offline `--version`/`--self-test`, signatures equal to the local build), and
   from an empty directory with a fresh `LMSCRIPT_TOOL_CACHE` and no local `lmaws` on `PATH`:
   `lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/recipe_quickstart.lms`
   must install the new version (`@latest` follows GitHub's Latest release).
6. Update `05-release.md` (current version, run id, proof file).

**If a release run fails.** Do not move or delete the tag (tags are immutable for users and
caches). Fix on `main`, bump to the next patch version and release that. Only a tag whose run never
published anything may be deleted, and only by the release owner:
`git push origin :refs/tags/vX.Y.Z` (after `gh release view vX.Y.Z` confirms there is no release).

**Why main can be ahead of @latest.** Raw-URL examples on `main` run against the latest release
binary; a recipe that needs an unreleased host method fails until the next release. New recipes
should use released host APIs, or ship together with a release.
