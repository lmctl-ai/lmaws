# Read-only cost attribution for tagged EC2 hosts

`Cloud.fleet_costs(spec_json, from, to)` returns JSON for a small, tag-selected
fleet. It uses existing SDK spend sources and the session's whole-run request
cap; the only accepted live profile is `default`. `aws.example` remains
synthetic unless explicitly enabled with `LMAWS_LIVE=1`.

The spec contains exactly `region` (currently `us-east-1`), `project`, `targets`
(1..10 objects with unique nonempty `name` and `role` strings), and one
`savings_plan_id` UUID. Discovery joins `Project`/`Role` tags, requiring exactly
one nonterminated instance per target. No account-specific identifiers belong
in public examples. Set `LMAWS_SPEND_REGIONS=us-east-1` to avoid unrelated
region inventory calls. Dates are UTC, start inclusive and end exclusive;
empty dates default to the current UTC month through the last complete day.

The JSON includes per-host on-demand pricing, attached gp3 disks, deduplicated
associated public IPv4, plan-rate references, charged CPU surplus during the
date range, and available resource-level Cost Explorer rows. Savings Plan
metadata and actual plan rates are included separately. The SDK normalizes
the AWS rate property's `productDescription` (for example Linux/UNIX), not
an invented `operatingSystem` property. Currency is USD.

Monthly references use current inventory and 730 hours, not historical disk
sizes, uptime or IP associations. gp3 capacity/performance and IPv4 use stated
US East reference tariffs. Surplus for Linux T4g is charged vCPU-minutes / 60
* $0.04; missing/partial metrics stay unknown. Pending credits are not charges.

The fixed plan commitment is counted once, including unused commitment. Its
upfront purchase amount is not added again. `with_plan_base_monthly_usd` is a
scenario assuming that plan is allocated to the selected eligible hosts and
has sufficient commitment. Rate availability alone is not proof of actual
per-host coverage in a shared account. For an all-upfront plan, a separate
recurring baseline excludes that prepaid commitment. Neither total includes
historical period CPU charges with a different time denominator.

Resource history is limited to the last 14 days and requires opt-in; the report
never enables it. Historical per-instance amounts are unknown if unavailable,
not zero. Whole-account EC2/Savings Plan/public-IP billing lines are retained
as cross-checks and never assigned wholesale to selected hosts. Other products,
tax, bandwidth, snapshots, unassociated IPs and unattached disks are excluded.
Look at `mode`, `status`, `warnings`, individual field statuses, date windows
and `assumptions` before interpreting a total.

`FleetCostsChecks` exercises arithmetic, deduplication, unknowns and plan
double-count prevention without credentials. `SpendSourceChecks` uses loopback
AWS protocol fixtures for inventory tags, plan metadata and paginated rates.
