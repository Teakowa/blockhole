# Detection policy

The policy is transparent and configured in `config/policy.toml`. It combines
independent signals: weighted request volume, path breadth, suspicious probe
matches, error ratio, repeated collection windows, and activity across zones.

No single URI, user agent, country, ASN, or sampled event can block an IP.
Automatic blocking requires at least two matching suspicious paths, at least
one corroborating signal, and a score meeting the configured threshold. Request
volume and repeated windows are weak corroboration; path breadth and activity
across zones are retained as evidence but do not add blocking score. Observed
counts and weighted estimates remain separate; weighted values are not exact
request totals. Security Analytics uses
adaptive sampling, so rare IPs may not appear and repeated queries can vary
slightly with sampling resolution. The number of observed IPs must therefore
not be interpreted as an exact malicious density for a network.

The analytics query groups by client IP, response status, and
`clientRequestPath`. Query strings are removed before paths are retained. The
configured `suspicious_path_patterns` identify probe-like paths; these paths
are the required primary signal and still cannot block an IP on their own.

The allowlist is evaluated before scoring and takes precedence over all blocks,
including manually imported `permanent_blocked` records. When a `permanent_blocked`
record matches an allowlist entry, it is retained in state with `suppressed_by_allowlist: true`
and excluded from active denylists. If the allowlist entry is later removed, the permanent
block automatically reactivates. Entries may be individual IPv4 or IPv6 addresses or
networks. Invalid entries fail validation. Do not add broad ASN or country exemptions
as a substitute for explicit allowlist entries.

Automatic records move through `candidate`, `temporary_blocked`, `cooldown`,
and `expired` states. Manually imported records use `permanent_blocked` and
have no TTL. Every automatic block has a TTL. Existing records are re-evaluated against the
current policy, so a block that no longer has the required scanning evidence is
released to `candidate`. Repeated activity may extend a block only within the
configured limit. Scores decay deterministically, and all times are UTC-aware.

The configured rollout mode is `enforce`. Use dry-run for validation or when
reviewing a materially broader policy before enabling remote synchronization.
