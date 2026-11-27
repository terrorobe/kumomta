use super::broken_first_choice_mx::deliver_via_backup;
use crate::kumod::{DaemonWithMaildir, DaemonWithMaildirOptions, MailGenParams};
use anyhow::Context;
use kumo_api_client::Metric;
use kumo_log_types::smtp::SmtpDispositionFields;
use kumo_log_types::RecordType::{Delivery, Reception, Rejection, TransientFailure};
use rfc5321::EnhancedStatusCode;
use serde_json::Value;
use std::collections::BTreeMap;
use std::time::Duration;

fn telemetry_options(mode: &str) -> DaemonWithMaildirOptions {
    DaemonWithMaildirOptions::new().env("KUMOD_TEST_SMTP_TELEMETRY", mode)
}

// Called after stop_both(), when the source has finished writing its segments.
fn closed_connection_records(daemon: &DaemonWithMaildir) -> anyhow::Result<Vec<Value>> {
    let mut records = Vec::new();
    for entry in std::fs::read_dir(daemon.source.dir.path().join("connections"))? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            let data = zstd::stream::decode_all(std::fs::File::open(entry.path())?)?;
            for line in std::str::from_utf8(&data)?.lines() {
                records.push(serde_json::from_str(line)?);
            }
        }
    }
    Ok(records)
}

#[tokio::test]
async fn mx_failover() -> anyhow::Result<()> {
    let mut daemon = telemetry_options("1").start().await?;
    deliver_via_backup(&daemon).await?;

    // The failed first host and the mixed plan are `other`; only the backup
    // and its successful transaction belong to `sink`.
    let api = daemon.source.api_client();
    let samples = api
        .get_metrics(|m| {
            let family = m.name().strip_prefix("smtp_client_")?;
            let connect_error =
                m.label_is("phase", "tcp_connect") && m.label_is("outcome", "error");
            let (group, outcome) = match family {
                "setup_first_candidate_total" => ("other", "failed"),
                "plan_attempts" | "setup_duration_seconds" => ("other", "ready"),
                "setup_phase_duration_seconds" if connect_error => ("other", "error"),
                "transaction_duration_seconds" => ("sink", "accepted"),
                _ => return None,
            };
            assert!(
                m.label_is("destination_relay_group", group) && m.label_is("outcome", outcome),
                "{m:?}"
            );
            if let Metric::Histogram(h) = m {
                assert_eq!(h.count, 1.0, "{m:?}");
            }
            Some((family.to_string(), m.value()))
        })
        .await?;
    let samples = BTreeMap::from_iter(samples);
    assert_eq!(samples["setup_first_candidate_total"], 1.0);
    assert_eq!(samples["plan_attempts"], 2.0);
    daemon.stop_both().await?;

    // The failed endpoint gets a connection record; the clean backup appears only in Delivery.
    let records = closed_connection_records(&daemon)?;
    let [attempt] = records.as_slice() else {
        anyhow::bail!("expected only the failed attempt, got {records:?}")
    };
    assert_eq!(attempt["type"], "SmtpConnection");
    assert_eq!(attempt["event"], "attempt");
    assert_eq!(attempt["attempt_number"], 1);
    assert_eq!(attempt["mx"], "brokenhost");
    assert_eq!(attempt["ip"], "255.255.255.255");
    assert_eq!(attempt["outcome"], "failed");
    assert_eq!(attempt["smtp_stage"], "tcp_connect");
    assert!(
        matches!(
            attempt["failure_kind"].as_str(),
            Some("connect_error" | "connect_refused" | "connect_timeout")
        ),
        "{attempt}"
    );
    assert!(attempt.get("connection_id").is_none());
    assert!(attempt.get("peer_replies").is_none());
    let elapsed_ms = attempt["elapsed_ms"]
        .as_f64()
        .context("missing attempt duration")?;
    assert!(elapsed_ms >= samples["setup_phase_duration_seconds"] * 1000.0);

    let logs = daemon.source.collect_logs().await?;
    assert!(!logs.iter().any(|r| r.kind == TransientFailure));
    let delivery = logs
        .into_iter()
        .find(|r| r.kind == Delivery)
        .context("missing Delivery")?;
    let peer = delivery.peer_address.context("missing Delivery peer")?;
    assert_eq!(peer.name, "workinghost");
    let session = delivery.session_id.context("missing Delivery session ID")?;
    assert_eq!(attempt["session_id"], session.to_string());
    let smtp = delivery.smtp.context("missing Delivery telemetry")?;
    assert!(smtp.connection_id.is_some());
    assert_eq!(smtp.transaction_number, Some(1));
    for (family, millis) in [
        ("setup_duration_seconds", smtp.connection_setup_ms),
        ("transaction_duration_seconds", smtp.transaction_elapsed_ms),
    ] {
        assert_eq!(
            Duration::from_secs_f64(samples[family]),
            Duration::from_secs_f64(millis.context(family)? / 1000.0),
            "{family}"
        );
    }
    Ok(())
}

async fn submit_for_transient_failures(
    daemon: &DaemonWithMaildir,
    messages: &[MailGenParams<'_>],
    timeout: Duration,
) -> anyhow::Result<()> {
    let mut client = daemon.smtp_client().await?;
    for message in messages {
        assert_eq!(message.send(&mut client).await?.code, 250);
    }
    let count = messages.len();
    assert!(
        daemon
            .wait_for_source_summary(|s| s.get(&TransientFailure) == Some(&count), timeout)
            .await,
        "expected {count} source TransientFailure records"
    );
    Ok(())
}

async fn metric_samples<T>(
    daemon: &DaemonWithMaildir,
    family: &str,
    sample: impl Fn(&Metric) -> T,
) -> anyhow::Result<Vec<T>> {
    daemon
        .source
        .api_client()
        .get_metrics(|m| (m.name().as_str() == family).then(|| sample(m)))
        .await
}

async fn assert_peer_refusals(
    daemon: &DaemonWithMaildir,
    expected: &[([&str; 3], f64)],
) -> anyhow::Result<()> {
    let mut refusals = metric_samples(daemon, "smtp_client_peer_refusals_total", |m| {
        let keys = ["destination_relay_group", "smtp_code", "reason"];
        assert_eq!(m.labels().len(), keys.len(), "{m:?}");
        (keys.map(|key| m.labels()[key].to_string()), m.value())
    })
    .await?;
    refusals.sort_by(|a, b| a.0.cmp(&b.0));
    let expected: Vec<_> = expected
        .iter()
        .map(|(labels, n)| (labels.map(str::to_owned), *n))
        .collect();
    assert_eq!(refusals, expected);
    Ok(())
}

#[tokio::test]
async fn auth_refusal_logs_peer_text_not_client_credentials() -> anyhow::Result<()> {
    let mut daemon = telemetry_options("classify")
        .env("KUMOD_SMTP_AUTH_USERNAME", "client-only-user")
        .env("KUMOD_SMTP_AUTH_PASSWORD", "client-only-password")
        .start()
        .await?;
    let message = MailGenParams::default();
    submit_for_transient_failures(&daemon, &[message], Duration::from_secs(10)).await?;
    // The classifier checks the numeric enhanced code even though AUTH text is withheld.
    assert_peer_refusals(&daemon, &[(["sink", "535", "auth_failed"], 1.0)]).await?;
    daemon.stop_both().await?;

    let records = closed_connection_records(&daemon)?;
    let [attempt] = records.as_slice() else {
        anyhow::bail!("expected one failed AUTH attempt, got {records:?}");
    };
    assert_eq!(attempt["event"], "attempt");
    assert_eq!(attempt["outcome"], "failed");
    assert_eq!(attempt["smtp_stage"], "auth");
    assert_eq!(attempt["failure_kind"], "smtp_reply");
    assert_eq!(
        attempt["peer_replies"],
        serde_json::json!([{"smtp_stage": "auth", "response": {
            "code": 535, "enhanced_code": {"class": 5, "subject": 7, "detail": 8},
            "reason": "auth_failed", "content": "AUTH invalid"
        }}])
    );
    let json = attempt.to_string();
    // Check both the plain credentials and the base64 AUTH PLAIN initial response.
    assert!(!json.contains("client-only-"));
    assert!(!json.contains("AGNsaWVudC1vbmx5LXVzZXIAY2xpZW50LW9ubHktcGFzc3dvcmQ="));
    Ok(())
}

#[tokio::test]
async fn pipelined_refusals_on_reused_connection() -> anyhow::Result<()> {
    let mut daemon = telemetry_options("classify")
        .env("KUMOD_TEST_SMTP_SLOW_THRESHOLD", "0s")
        .env("KUMOD_TEST_SINK_CLIENT_TIMEOUT", "1m")
        .start()
        .await?;
    let messages = [
        "retry-short@example.com",
        "retry-long@example.com",
        "full@example.com",
    ]
    .map(|recip| MailGenParams {
        recip: Some(recip),
        ..Default::default()
    });
    submit_for_transient_failures(&daemon, &messages, Duration::from_secs(50)).await?;

    // Both 450 replies increment the same counter, despite distinct enhanced codes.
    // The consequential DATA refusals remain in the logs below, not the counter.
    assert_peer_refusals(
        &daemon,
        &[
            (["sink", "450", "temporary"], 2.0),
            (["sink", "452", "other"], 1.0),
        ],
    )
    .await?;
    let builds = metric_samples(
        &daemon,
        "smtp_client_setup_address_list_build_duration_seconds",
        |m| {
            assert!(m.as_histogram().count >= 1.0, "{m:?}");
            m.labels()["outcome"].to_string()
        },
    )
    .await?;
    assert_eq!(builds, ["complete"]);
    let plan_groups = metric_samples(&daemon, "smtp_client_plan_attempts", |m| {
        m.labels()["destination_relay_group"].to_string()
    })
    .await?;
    assert_eq!(plan_groups, ["sink"]); // the skipped IPv6 backup is not in the plan
    let mut uses = metric_samples(&daemon, "smtp_client_transactions_total", |m| {
        (m.labels()["connection_use"].to_string(), m.value())
    })
    .await?;
    uses.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(uses, [("first".into(), 1.0), ("reused".into(), 2.0)]);
    daemon.stop_both().await?;

    // The zero threshold selects both the localhost lookup and its ready socket without a delay.
    let connections = closed_connection_records(&daemon)?;
    let ready = connections
        .iter()
        .find(|r| r["event"] == "attempt" && r["outcome"] == "smtp_ready")
        .context("missing SMTP-ready attempt")?;
    let session = ready["session_id"].as_str().context("missing session ID")?;
    let build = connections
        .iter()
        .find(|r| r["event"] == "address_list" && r["session_id"] == session)
        .context("missing address_list record for ready socket")?;
    assert_eq!(build["outcome"], "complete");
    assert!(build["usable_ip_candidates"]
        .as_u64()
        .is_some_and(|n| n > 0));
    assert!(build["address_list_build_ms"]
        .as_f64()
        .is_some_and(|ms| ms >= 0.0));
    assert!(build.get("connection_id").is_none());

    let sink = daemon.sink.summarize_logs().await?;
    assert_eq!(sink, BTreeMap::from([(Rejection, 6)]));
    let stats = daemon.source.accounting_stats()?;
    assert_eq!((stats.received, stats.delivered), (3, 0));
    let logs = daemon.source.collect_logs().await?;
    let (received, failures) = logs
        .into_iter()
        .partition::<Vec<_>, _>(|r| r.kind == Reception);
    assert_eq!((received.len(), failures.len()), (3, 3));
    let clipped = "x".repeat(255);
    for (code, class, reason, content, truncated) in [
        (450, Some(4), "temporary", "tempfail requested", None),
        (450, Some(5), "temporary", clipped.as_str(), Some(true)),
        (452, None, "other", "mailbox is full", None),
    ] {
        let enhanced = class.map(|class| EnhancedStatusCode {
            class,
            subject: 7,
            detail: 1,
        });
        let failure = failures
            .iter()
            .find(|r| r.response.code == code && r.response.enhanced_code == enhanced)
            .with_context(|| format!("missing RCPT refusal {code} {enhanced:?}"))?;
        assert_eq!(failure.kind, TransientFailure);
        let smtp = failure.smtp.as_ref().context("missing SMTP telemetry")?;
        assert_eq!(smtp.smtp_stage, Some("rcpt_to".into()));
        let primary = smtp.peer_response.as_ref().context("missing RCPT reply")?;
        assert_eq!(primary.code, code);
        assert_eq!(primary.enhanced_code, enhanced);
        assert_eq!(primary.reason, Some(reason.into()));
        assert_eq!(primary.content.as_deref(), Some(content));
        assert_eq!(primary.content_truncated, truncated);
        let [secondary] = smtp.peer_replies.as_slice() else {
            anyhow::bail!("expected a secondary DATA refusal: {smtp:?}")
        };
        assert_eq!(secondary.response.code, 503);
        assert_eq!(secondary.smtp_stage.as_str(), "data");
        assert_eq!(secondary.response.reason, Some("other".into()));
        assert_eq!(
            secondary.response.content.as_deref(),
            Some("RCPT TO must be issued first")
        );
    }
    Ok(())
}

async fn submit_deferred_batch(
    daemon: &DaemonWithMaildir,
    message: MailGenParams<'_>,
) -> anyhow::Result<()> {
    let mut client = daemon.smtp_client().await?;
    assert_eq!(message.send_batch(&mut client).await?.response.code, 250);
    assert!(
        daemon
            .wait_for_source_summary(
                |s| s.contains_key(&TransientFailure),
                Duration::from_secs(10)
            )
            .await
    );
    Ok(())
}

#[tokio::test]
async fn unretained_recipient_refusal_counts_but_secondary_data_does_not() -> anyhow::Result<()> {
    let mut daemon = telemetry_options("classify")
        .env("KUMOD_BATCH_HANDLING", "BatchByDomain")
        .start()
        .await?;
    // Fill the eight retained slots. The next RCPT would normally classify as `temporary`;
    // its result must still count as `other`, while the omitted pipelined DATA 503 must not count.
    let mut recipients: Vec<_> = (0..8)
        .map(|i| format!("tempfail-{i}@example.com"))
        .collect();
    recipients.push("retry-short@example.com".to_owned());
    let message = MailGenParams {
        recip_list: Some(recipients.iter().map(String::as_str).collect()),
        ..Default::default()
    };
    submit_deferred_batch(&daemon, message).await?;
    assert_peer_refusals(
        &daemon,
        &[
            (["sink", "400", "other"], 8.0),
            (["sink", "450", "other"], 1.0),
        ],
    )
    .await?;
    daemon.stop_both().await
}

async fn data_dot_failure(
    options: DaemonWithMaildirOptions,
    outcome: &str,
    refusals: &[([&str; 3], f64)],
) -> anyhow::Result<SmtpDispositionFields> {
    let mut daemon = options
        .env("KUMOD_BATCH_HANDLING", "BatchByDomain")
        .start()
        .await?;
    let message = MailGenParams {
        sender: Some("disconnect-in-data-no-421@example.com"),
        recip_list: Some(vec!["first@example.com", "second@example.com"]),
        ..Default::default()
    };
    submit_deferred_batch(&daemon, message).await?;
    assert_peer_refusals(&daemon, refusals).await?;
    let outcomes = metric_samples(&daemon, "smtp_client_transaction_duration_seconds", |m| {
        (m.labels()["outcome"].to_string(), m.as_histogram().count)
    })
    .await?;
    assert_eq!(outcomes, [(outcome.to_string(), 1.0)]);
    daemon.stop_both().await?;

    let record = daemon
        .source
        .collect_logs()
        .await?
        .into_iter()
        .find(|r| r.kind == TransientFailure)
        .context("missing TransientFailure")?;
    assert_eq!(record.response.code / 100, 4);
    let smtp = record.smtp.context("missing failure telemetry")?;
    assert_eq!(smtp.smtp_stage, Some("data_dot".into()));
    Ok(*smtp)
}

#[tokio::test]
async fn data_dot_peer_refusal() -> anyhow::Result<()> {
    // One DATA-dot reply decided both recipients' results in a single transaction.
    let expected = [(["sink", "451", "other"], 2.0)];
    let smtp = data_dot_failure(telemetry_options("1"), "deferred", &expected).await?;
    assert_eq!(smtp.failure_kind, Some("smtp_reply".into()));
    let peer = smtp.peer_response.context("missing peer reply")?;
    assert_eq!(peer.code, 451);
    assert_eq!(peer.reason, Some("other".into()));
    assert_eq!(
        peer.content.as_deref(),
        Some("disconnecting disconnect-in-data-no-421")
    );
    Ok(())
}

#[tokio::test]
async fn data_dot_timeout() -> anyhow::Result<()> {
    // The same peer withholds its 451 until after the client's DATA-dot deadline.
    let options = telemetry_options("1")
        .env("KUMOD_TEST_DATA_DOT_TIMEOUT", "100ms")
        .env("KUMOD_TEST_SINK_DATA_DOT_DELAY", "2");
    let smtp = data_dot_failure(options, "transport_error", &[]).await?;
    assert_eq!(smtp.failure_kind, Some("response_timeout".into()));
    assert_eq!(smtp.transaction_number, Some(1));
    assert!(smtp.peer_response.is_none() && smtp.peer_replies.is_empty());
    Ok(())
}

#[tokio::test]
async fn unused_ready_connection() -> anyhow::Result<()> {
    let mut daemon = telemetry_options("unused")
        .env("KUMOD_HIDE_8BITMIME", "1")
        .start()
        .await?;
    // One message per socket: delivery, RCPT refusal, and a local 8BITMIME
    // failure before MAIL FROM. Only the last SMTP-ready socket is unused.
    let mut client = daemon.smtp_client().await?;
    for (recip, subject) in [
        ("ok@example.com", "plain"),
        ("tempfail@example.com", "plain"),
        ("unused@example.com", "👾"),
    ] {
        let content = format!("Subject: {subject}\r\n\r\nbody\r\n");
        let mail = MailGenParams {
            recip: Some(recip),
            full_content: Some(&content),
            ignore_8bit_checks: true,
            ..Default::default()
        };
        assert_eq!(mail.send(&mut client).await?.code, 250);
    }
    daemon
        .source
        .wait_for_metric(
            Duration::from_secs(10),
            |m| {
                if m.name().as_str() != "smtp_client_transactions_per_connection"
                    || !m.label_is("destination_relay_group", "sink")
                {
                    return false;
                }
                let h = m.as_histogram();
                let (sum, zeros) = match m.labels()["measure"].as_str() {
                    "attempted" => (2.0, 1.0),
                    "accepted" => (1.0, 2.0),
                    _ => return false,
                };
                (h.count, h.sum, h.bucket[0]) == (3.0, sum, (0.5, zeros))
            },
            |values| values.len() == 2,
        )
        .await
        .context("waiting for unused socket to close")?;
    daemon.stop_both().await
}
