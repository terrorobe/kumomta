# kumo.configure_smtp_client_telemetry

{{since('dev')}}

Enables outbound SMTP client telemetry. Without this call the telemetry is disabled. Call it from [init](../events/init.md). The allowlists are fixed for the lifetime of the process; restart to change them. An empty configuration enables telemetry with empty allowlists.

```lua
kumo.on('init', function()
  kumo.configure_smtp_client_telemetry {
    providers = {
      example_gateway = { 'mx.example.net', '=smtp.example.org' },
    },
    reasons = { 'rate_limited' },
  }
end)
```

* `providers` maps a group to SMTP next-hop hostname rules. A bare domain matches that domain and its descendants; `*.example.net` matches descendants only; `=smtp.example.net` matches only that host. Matching is case-insensitive, ignores a final root dot and port, and prefers the longest matching domain. Use ASCII DNS names or their Punycode forms. The first-candidate counter uses the first IP's MX group. Plan metrics use the candidates remaining after address caps and filtering. An unmatched host or mixed plan maps to `other`; missing MX information maps to `unknown`. The MX lookup phase uses `unknown` and measures ready-queue name resolution, including cache hits and admin egress-path inspection, but not address literals.
* `reasons` lists labels that [smtp_client_classify_peer_reply](../events/smtp_client_classify_peer_reply.md) may assign to a negative peer reply. The default is `other`.

At most 32 provider groups, 128 hostname rules in total, and 16 reason labels are accepted. Provider and reason labels start with a lowercase ASCII letter and contain at most 48 lowercase letters, digits or underscores. `other` and `unknown` are reserved provider groups.

The `smtp_client_` counters and histograms appear at the [metrics endpoint](../http/kumod/metrics_get.md) as observations occur. Duration histograms use seconds. Attempts and transactions per connection are histogram values, not labels. Each classic histogram exports one series per finite bucket, plus `+Inf`, sum and count.

During delivery, [smtp_client_peer_refusals_total](../metrics/kumod/smtp_client_peer_refusals_total.md) counts the selected negative peer reply once per affected recipient, before policy rewrites. For example, if the peer refuses `RCPT TO` with `450` and then refuses a pipelined `DATA` with `503`, only the `450` counts. Retained secondary replies remain in the transaction log. During connection setup or while idle, each negative peer reply counts once. Replies with the same `destination_relay_group`, `smtp_code` and `reason` share one counter, even when their enhanced status codes differ. The [logged peer reply](../log_record.md#outbound-smtp-disposition-fields) preserves the enhanced status code if supplied. Reply text and addresses are never labels. Locally assigned status codes, including those for timeouts, do not count as peer replies.
