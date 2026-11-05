# Read-only CloudFront viewer traffic

For existing S3 access logs and status/User-Agent investigation, see
[read-only CloudFront log retrieval](CLOUDFRONT_LOGS.md).

`Cloud.cloudfront_traffic(domain, startISO, endISO)` returns JSON with matching
CloudFront distributions and hourly Requests, BytesDownloaded, 4xxErrorRate
and 5xxErrorRate. Dates may be UTC `YYYY-MM-DD` or ISO instants; the end is
exclusive and clamped to the current UTC instant. Requested ranges must be
at most 31 days. Synthetic mode generates deterministic hourly data.

Only the default profile is accepted for live calls, with a `us-east-1`
backend. Distribution discovery uses paginated ListDistributions and matches
the supplied DNS name plus its www/bare variant. Metrics use namespace
AWS/CloudFront, dimensions DistributionId and Region=Global. Requests and
BytesDownloaded use Sum; error rates use Average. Partial status, malformed
results, missing data and nonfinite values are not converted to zero.

The projection contains distribution ID/domain/aliases, enabled status,
origin domain names, Web ACL ID, and legacy S3 logging status/bucket. Origin
custom headers, cookies, key material and full distribution configuration are
never returned. Legacy logging status does not establish whether newer
CloudWatch delivery destinations are configured.

The request ledger tracks query estimates under the session's whole-run cap.
The collector never enables paid metrics/logging, changes WAF or distribution
configuration, reads access logs, invalidates paths, or uses admin credentials.

Request counts cover all assets/methods and all aliases on a distribution;
they are not unique visitors, GA4 sessions or origin-request counts. Standard
distribution metrics have no client-country, IP, URL or user-agent breakdown.
Compare trends rather than equating HTTP counts to analytics users.

`CloudFrontTrafficChecks` uses SDK proxies for pagination, exact metric
dimensions/statistics, missing/partial values and safe config projection.
Run after building with the dummy loopback endpoint (no connection occurs):

```bash
AWS_PROFILE=default LMAWS_ENDPOINT=http://127.0.0.1:9 \
  java -cp target/lmaws-0.1.27.jar ai.lmctl.lmaws.CloudFrontTrafficChecks
```

Reference: [AWS metric definitions and required dimensions](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/programming-cloudwatch-metrics.html).
