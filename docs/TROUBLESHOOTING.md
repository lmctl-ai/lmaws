# Troubleshooting

| Message (or symptom) | Cause | Fix |
|---|---|---|
| `--profile must be default (read-only), lmaws (service sandboxes) or lmaws-ec2 ...` | Unknown profile name | Use a profile from [PROFILES.md](PROFILES.md) |
| `a live sandbox needs --live --apply --profile lmaws` | Write recipe without `--apply` or with a read-only profile | Add `--live --apply --profile lmaws` (EC2: `lmaws-ec2`) |
| `live mutations require AWS_PROFILE=lmaws or lmaws-ec2 (active profile: ...)` | A host program tried to write with another profile | Export `AWS_PROFILE=lmaws` for owned sandboxes |
| `The 'admin' profile is reserved exclusively for lmaws_ IAM policy grants` | `admin` used for a non-IAM write | Use `lmaws`; `admin` is only for the grant recipes |
| `live writes require LMAWS_LIVE=1` | Host program run directly without live mode | Recipes set it from `--live`; direct runs export `LMAWS_LIVE=1` |
| `live AWS credentials are disabled in CI` | `CI=true` in the environment | Expected in CI; run live tests locally |
| `AWS scoped profile unavailable; check the isolated source profile and session policy; agents never use admin.` | `--credential-process` could not read the selected static issuer, load the session policy, or STS refused issuance | `lmctl recipes/session_doctor.lms --live`; check the explicitly selected issuer (default `agent-issuer`) and session policy file; agents never use admin |
| `AWS AccessDenied (HTTP 403)` / `UnauthorizedOperation` | The session policy does not allow the call | `lmctl examples/recipe_policy_explain_denial.lms` explains denials; ask an administrator |
| `unknown recipe argument --x` | Typo in a flag | The `# Arguments:` line at the top of every recipe lists its flags |
| `--top must be a whole number 1..1000; got NaN` | A flag value is not a number | Pass a number, e.g. `--top 10` |
| `estimated cost cap exceeded before ... (LMAWS_MAX_COST_USD)` | The run would exceed its cost cap (default $0.05, hard $0.25) | Raise `--cap` (max 0.25) or run fewer live recipes in one script |
| `Recipe whole-run cap exceeded` | Several live recipes in one script reserved more than $0.25 | Split the script or lower per-recipe `--cap` |
| `leftover count is N; inspect the run ledger` | Teardown could not prove every resource is gone | Re-run the recipe's recovery (`--live --apply` cleanup by prefix, `cloud.spot_recover("<run id>")`, `web.down()`) and read `.lmaws-local/` ledgers |
| `Live recipes on Windows: set X=... in the parent environment first.` | lmscript 0.2.426-0.2.428 does not pass `set_env` to child processes on Windows | Export the printed variables before running, or use Linux/macOS |
| Picture is missing (`images/` empty) | lmplot could not be installed | Check network access to GitHub releases; `lmctl` installs lmplot on first use |
| An example reports an unknown method | The released `lmaws` (`install=@latest`) is older than `main` | Wait for the next release, or build locally (`mvn -q package`) and put the JVM wrapper on `PATH` |

Live results, ledgers and evidence always stay in the git-ignored `.lmaws-local/` directory of
the working directory; nothing is uploaded or committed.
