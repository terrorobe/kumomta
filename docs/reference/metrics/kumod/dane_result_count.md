# dane_result_count

```
Type: Counter
Labels: result
```
Number of DANE policy decisions made on the SMTP delivery path, labelled by `result`.


!!! info
    This metric has labels which means that the system will track the metric for each combination of the possible labels that are active.  Certain labels, especially those that correlate with source or destination addresses or domains, can have high cardinality.  High cardinality metrics may require some care and attention when provisioning a downstream metrics server.

{{since('2026.09.22-a276d4a8')}}

The `result` label is one of:

  * `ok`: usable DANE-TA(2)/DANE-EE(3) TLSA records were found; DANE
    authentication is required, via a handshake or matching session evidence.
    This is not a count of successful handshakes or deliveries.
  * `unusable`: TLSA records were published but none are usable; STARTTLS is
    required, but these records cannot authenticate the peer.
  * `not_applicable`: the chain to the MX host was DNSSEC-validated but there
    are no TLSA records (securely absent), so DANE does not apply.
  * `insecure_chain`: DANE is enabled but the chain to the MX host was not
    DNSSEC-validated, so DANE does not apply. A persistently high value here
    with none of the other results can indicate that the resolver is not
    performing DNSSEC validation.
  * `tempfail`: the MX address-chain or TLSA lookup failed, was bogus, or
    no longer provided addresses for a retained candidate. That candidate
    cannot be used for this attempt.

These counters include connection setup and DNS-MX connection-reuse checks.
They count policy evaluations, not unique messages, network DNS queries or
handshakes; one message can cause multiple evaluations. Reason about them as
rates, allowing for changes in connection reuse and traffic mix.

**Confirming DANE is working:** with `enable_dane = true`, a healthy
deployment shows a steady stream of `not_applicable` (most DNSSEC-signed
domains do not publish TLSA records) plus some `ok` for the destinations
that do. The single most useful health check is: if you only ever see
`insecure_chain` and never `ok` or `not_applicable`, your
resolver is almost certainly not performing DNSSEC validation, so DANE is
silently doing nothing — verify that you configured a validating resolver.
For an ad-hoc check that does not require standing up a sink or large-scale
test, <https://havedane.net> publishes known-good TLSA records: send a test
message to an address there and confirm that `ok` increments.

**What to alert on:**

  * A sustained or rising rate of `tempfail` warrants investigation. It
    usually points at resolver or upstream-DNS trouble (SERVFAIL, timeouts,
    bogus answers), and only rarely at an active downgrade attempt. A failed
    reuse check defers the message; connection setup may still succeed via
    another authorized MX, so this is not a count of deferred messages.
  * `ok` pinned at zero while `insecure_chain` is high (with
    `enable_dane = true`) indicates a non-validating resolver, i.e. DANE is
    not engaging at all.
  * `unusable` is informational: a remote operator published TLSA records
    that are not usable for SMTP DANE (for example, only PKIX usages). A low
    background level is normal and reflects the remote side, not your
    infrastructure.
  * `not_applicable` and `insecure_chain` are expected in normal operation
    for the large fraction of destinations that do not publish usable TLSA
    records or are not DNSSEC-signed; do not alert on these in isolation.

