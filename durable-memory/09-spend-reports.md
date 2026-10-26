# Detailed read-only spend reports

`Cloud.spend(topic, days, top, cap)` returns a materialized `Spend` report.
Topics: all, ec2_spend, savings_plans, eip_audit, ebs_audit, bandwidth,
lambda_spend and dynamodb_spend. One report is the sole cost session per host
program. Default examples use deterministic fixtures, never credentials.

The host now has 94 own signatures (166 including the 72 implicit std entries).
AWS SDK remains 2.57.3; Cost Explorer, Savings Plans and Pricing add three JARs
to the 57 pinned runtime artifacts. New SDK reads use URLConnection, no retries,
request pacing, pagination bounds, cached grouped queries and no AWS CLI.

CE pages cost $0.01 in the primary billing view; GetMetricData counts metrics
requested per page. The cap is <=$0.25 and every billed attempt is admitted first.
Default synthetic all-topic report: 10 CE calls +18 metric units, $0.10018 modeled;
actual offline AWS charge is zero. Unknown/denied/disabled values remain explicit.

Live requires AWS_PROFILE=default, LMAWS_LIVE=1 and LMAWS_SPEND_LIVE=1; real
requests are forbidden in CI. Live inventory discovers enabled regions (an
explicit LMAWS_SPEND_REGIONS restricts scope); failed regions are flagged.
All live reports, ledgers and figures stay under ignored .lmaws-local/spend.
Never commit account spend, IDs, names, ARNs, IPs or live pictures/evidence.

CSV/JSON sections preserve details; five flagship charts show daily stacked
spend, service bars, idle-resource table, coverage gauge and transfer costs.
Monthly/MTD totals derive from cached daily service costs where possible. EC2
resource costs require opt-in and only cover 14 days; the tool never enables it.
EBS/snapshot/run-rate and workload prices are reference estimates, not invoices.

Local checks: 188 numeric/privacy/cap controls, 32 JVM SDK loopback controls plus native SDK wire validation,
12 API gate checks, all eight spend scripts and 12 synthetic figures. Managed/native gates passed, including all 88 examples; publication follows
the ordinary local gate. Live validation details remain
private; only synthetic evidence belongs in this repository.

See [the user guide](../docs/SPEND_REPORT.md) for sections, profiles, prices,
permissions, invocation and limitations. The original 30 IaC comparisons remain
separate; billing analysis is not claimed to be a Terraform apply equivalence.
