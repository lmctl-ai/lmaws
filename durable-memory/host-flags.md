# Host flag cutover

Only --lmcode, --lmcode-schema and --lmcode-signatures (including the existing
--without-std modifier) are accepted. Unknown operations are rejected before
CloudHost construction, client/credential setup and journals. The normal gate
checks all retired spellings, exact schema bytes, signatures and loader routing.

The Java SDK archive is synced with sync-sdk.py from immutable main 3ff5ca5e.
The source compiler is qualified by v6/signature capability, not its historical
package version. Use mono main after the flag cutover; old published compilers
cannot drive these host options. DSLB magic, .dslb paths, service and spend
safeguards and the existing host result diagnostics are unchanged.

The complete managed test.sh passes against private updated lmfiles and lmplot
builds. This includes actual demo provisioning/registry continuation, HTTP SDK
loopback fixtures, spend/upload/role/policy safeguards and ten recipe execution
controls. No AWS credentials or paid cloud request was needed. Native and live
qualification are separate; no global dependency was upgraded or relinked.
