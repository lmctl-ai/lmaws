# lmaws durable memory

- [01-architecture.md](01-architecture.md): typed host, dependency pins, safety model and scope.
- [02-build-test.md](02-build-test.md): JVM/native build, fake endpoints and memory enforcement.
- [03-live.md](03-live.md): approved default-profile live smoke and teardown protocol.
- [04-examples.md](04-examples.md): gallery, demo data and reproducible autoruns.
- [05-release.md](05-release.md): five-platform release proof and remaining limits.

Release evidence:
- [main-ci-v010.json](main-ci-v010.json): five green main platform jobs.
- [release-v010.json](release-v010.json): green tag publication, asset hashes and sizes.
- [autorun-v010.json](autorun-v010.json): 25 empty-directory released-native autoruns.
- [gallery-v010.json](gallery-v010.json): local gallery and deterministic CSV checks.
- [fake-jvm-v010.json](fake-jvm-v010.json), [fake-native-v010.json](fake-native-v010.json): SDK HTTP fixture coverage.
- [live-v010.json](live-v010.json): two approved live resources, both deleted.
- [ci-linux-readonly-v010.json](ci-linux-readonly-v010.json): actual CI binary credential/TLS reads.

v0.1.1 candidate:
- [07-example-costs.md](07-example-costs.md): cost policy and live authorization blocker.
- [cost-ci-v011.json](cost-ci-v011.json): five green fake-only platform jobs.
- [gallery-v011.json](gallery-v011.json): 30 offline examples and image checks.
- [validation-status-v011.json](../evidence/validation-status-v011.json): per-example live state and zero leftovers.
- [USER_TEST.md](../docs/USER_TEST.md): exact local environment, test and sweeper instructions; not ready while blocked.
