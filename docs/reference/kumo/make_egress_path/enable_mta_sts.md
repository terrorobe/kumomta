# enable_mta_sts

{{since('2023.11.28-b5252a41')}}

When set to `true` (which is the default), a resolved
[MTA-STS](https://datatracker.ietf.org/doc/html/rfc8461) policy for the
destination domain will be used to adjust the effective value of `enable_tls`.
You can set it to `false` to prevent a policy from raising the TLS posture for
this egress path.

{{since('2026.09.22-a276d4a8', indent=True)}}
    This option influences only whether the TLS portion of the MTA-STS policy
    is applied on this particular egress path.  It doesn't control whether the
    MTA-STS records are queried.  Since MTA-STS records can influence the
    effective *site_name*, they are now queried before we instantiate the
    egress path.
    [kumo.dns.set_mta_sts_enabled](../../kumo.dns/set_mta_sts_enabled.md)
    controls whether MTA-STS records are used.  In earlier versions,
    `enable_mta_sts` controlled both querying and TLS level, which could lead to
    broken routing for certain types of domains sharing the same MXs.

For example, for `gmail.com` we'll issue a TXT lookup for
`_mta-sts.gmail.com` and an HTTP GET for
`https://mta-sts.gmail.com/.well-known/mta-sts.txt` as described in the MTA-STS
RFC.  The latter resource returns the MTA-STS policy, which at the time of writing
looks like this for `gmail.com`:

```
version: STSv1
mode: enforce
mx: gmail-smtp-in.l.google.com
mx: *.gmail-smtp-in.l.google.com
max_age: 86400
```

The `mode` field describes the intended policy of the destination site, while
the `mx` fields place restrictions on the allowable list of MX hosts.

If the `mode` for the destination domain is set to `"enforce"`, then the
connection will be made with `enable_tls="Required"`. Candidate MX hosts that do
not match the `mx` fields are removed during resolution, so by the time a
connection is attempted the candidate set already satisfies the policy.

If the `mode` is set to `"testing"`, then the connection will be made
with `enable_tls="OpportunisticInsecure"`.

If the `mode` is set to `"none"`, then your configured value for `enable_tls`
will be used.

If `enable_dane=true` and usable `TLSA` records are present, DANE authentication
supersedes the MTA-STS TLS posture. Unusable TLSA records still require STARTTLS;
MTA-STS may add certificate validation but cannot relax that requirement. The MX
host filtering performed during resolution is independent of this TLS precedence.

The dispatcher applies the routing domain's effective TLS requirement to each
message, including when domains share an MX ready queue. It reuses a connection
only when that connection satisfies the requirement. DANE decisions are reused
only within the same unexpired domain/MX context; a change requires a fresh
connection-time evaluation.

A policy-driven reconnect does not itself reinsert other ready messages, but it
still observes the site's shared connection-rate limits and failure backoff.
Refreshing an expired MX/policy result can wait for DNS and HTTPS requests in the
dispatcher, delaying other messages when dispatch capacity is limited. Errors
returned by MX resolution defer the affected message. If MTA-STS retrieval fails
without a usable cached policy, the resolver proceeds without an MTA-STS override;
the configured TLS setting and any applicable DANE requirement still apply.
