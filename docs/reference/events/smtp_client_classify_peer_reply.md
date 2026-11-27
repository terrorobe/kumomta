# smtp_client_classify_peer_reply

{{since('dev')}}

With [outbound SMTP client telemetry](../kumo/configure_smtp_client_telemetry.md) enabled, this optional event classifies a genuine negative SMTP reply before disposition policy rewrites it. The arguments are a bounded provider group, an SMTP stage without arguments, and a table with `code`, an optional `enhanced_code` (numeric `class`, `subject`, `detail`), and optional `content`. At every stage the handler receives the peer's enhanced status code if supplied, even when its class differs from the SMTP reply code. There is no command or envelope. `content` is untrusted peer input. The handler receives no text for `auth`, `other` (unknown), `data_write` or `pipeline`, or when the text is incomplete or exceeds 1,024 UTF-8 bytes.

Return a table with a `reason` from the configured list. Only `reason` is used. For example:

```lua
kumo.on('smtp_client_classify_peer_reply', function(provider, stage, response)
  if stage == 'rcpt_to' and response.content == 'Recipient rate limit reached' then
    return { reason = 'rate_limited' }
  end
end)
```

If the handler is absent, fails, times out or returns no allowed reason, the reason is `other`. The handler cannot replace or suppress the [peer text in local logs](../log_record.md#outbound-smtp-disposition-fields) or change the SMTP disposition.

Keep the handler fast and local. Retained secondary replies also reach the classifier for logging, but do not increment the [refusal counter](../kumo/configure_smtp_client_telemetry.md). If a counted reply cannot be retained for classification, its reason is `other`.
