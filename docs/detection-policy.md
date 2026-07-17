# Detection policy

The policy is transparent and configured in `config/policy.toml`. It combines
independent signals: weighted request volume, path breadth, suspicious probe
matches, error ratio, repeated collection windows, and activity across zones.

No single URI, user agent, country, ASN, or sampled event can block an IP.
Automatic blocking requires at least two scored signals and a score meeting
the configured threshold. Observed counts and weighted estimates remain
separate; weighted values are not exact request totals.

The allowlist is evaluated before scoring. Entries may be individual IPv4 or
IPv6 addresses or networks. Invalid entries fail validation. Do not add broad
ASN or country exemptions as a substitute for explicit allowlist entries.

Records move through `candidate`, `blocked`, `cooldown`, and `expired` states.
Every automatic block has a TTL. Repeated activity may extend a block only
within the configured limit. Scores decay deterministically, and all times
are UTC-aware.

The initial rollout is dry-run. Review several days of reports and false
positives before enabling enforcement. A materially broader policy returns to
dry-run until explicitly approved.
