# Spend reports

`aws.spend(topic, days, top, cap)` creates one read-only spend session. It is
the sole cost-capped spend session in a host program. The `Spend` methods are
`section`, `json`, `write`, `is_demo`, `estimated_cost`, `ce_requests`,
`metric_requests`, and `metric_units`. Sections contain explicit `observed`,
`no_data`, `unavailable`, `partial`, or budget-exhausted statuses.

Topics are `all`, `ec2_spend`, `savings_plans`, `eip_audit`, `ebs_audit`,
`bandwidth`, `lambda_spend`, and `dynamodb_spend`. Examples default to 30 days,
top 10, and a $0.25 cap. The end date is UTC today, exclusive. Short windows
derive the month-to-date headline from cached daily Cost Explorer data and may
make an additional daily query. A default fake `all` run uses ten CE pages and
18 CloudWatch metric units as a planning estimate; its actual AWS charge is $0.
The ledger charges CE pages at $0.01 and includes CloudWatch units in the same
cap; the hard cap is $0.25. A cap refusal propagates as an incomplete report.

The live source uses the default AWS profile only and is read-only. `LMAWS_LIVE=1`
and `LMAWS_SPEND_LIVE=1` are both required, CI is refused, and the user must
explicitly opt into the one local run. `LMAWS_SPEND_REGIONS` restricts inventory
and metrics; without it, enabled regions are enumerated. Cost Explorer uses the
primary global billing view. All dates and metric windows are UTC. AWS CLI is
never invoked, and CI has no cloud credentials. Loopback `LMAWS_ENDPOINT` is
reserved for fake SDK protocol tests.

Inventory is read-only and includes EC2 instances, EIPs, EBS volumes, snapshots,
reserved instances, Lambda functions, and DynamoDB tables. Public IPv4 reporting
combines EIPs and ENI/EC2 associations with deduplication; it is not an account-
wide IPAM claim. EC2 resource cost is an opt-in 14-day view, not a claim that
historical inventory rows carry exact age costs. Snapshot size is an upper bound,
not incremental billed storage. EBS references current regional gp2/gp3/io1/io2
and IOPS assumptions. Missing CloudWatch data stays unknown. Lambda GB-seconds
use `Duration` milliseconds × current memory MB / 1,024,000; DynamoDB output
retains size/item-count freshness and documents regional read/write/storage
reference rates rather than inventing usage.

Reference estimates include $0.005 per public IPv4 hour for an associated or idle
address and $3.65 for 730 hours. They exclude tax, credits, free tiers and
discounts; AWS prices vary by region and time. See [AWS public IPv4 pricing](https://aws.amazon.com/vpc/pricing/),
[EBS pricing](https://aws.amazon.com/ebs/pricing/), [Lambda pricing](https://aws.amazon.com/lambda/pricing/),
and [DynamoDB pricing](https://aws.amazon.com/dynamodb/pricing/).

Demo examples write deterministic CSV/JSON/PNG files under `data/` and `images/`.
Live output is forced under private `.lmaws-local/spend/`; reports contain masked
account data and never publish real IDs, ARNs, IPs or names. Live CSV/JSON/PNG
artifacts must never be committed. `Spend.write(path)` writes the report and
section CSV and JSON files; `Spend.json()` returns the redacted JSON.

The flagship `spend_detail` presents five lmdraw views: stacked spend over time,
service bars, an idle-resource table, a Savings Plan coverage gauge, and a
transfer breakdown. The public gallery remains fake-only. The existing 30
native/lmcloud comparisons are unchanged; new SDK billing reports are not
Terraform-apply equivalence proof.

Live testing is intentionally pending. A future user-run smoke test must review
the private report and permissions first; this document makes no live numeric
claim. CI uses fake transports only.
